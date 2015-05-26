#include <linux/bpf.h>

#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/RecordLayout.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Rewrite/Core/Rewriter.h>

#include "b_frontend_action.h"

extern "C"
int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
                   int max_entries);

namespace ebpf {
using std::map;
using std::string;
using std::unique_ptr;
using namespace clang;

BTypeVisitor::BTypeVisitor(ASTContext &C, Rewriter &rewriter, map<string, BPFTable> &tables)
    : C(C), rewriter_(rewriter), out_(llvm::errs()), tables_(tables) {
}

bool BTypeVisitor::VisitFunctionDecl(FunctionDecl *D) {
  return true;
}

// convert calls of the type:
//  table.foo(&key)
// to:
//  bpf_table_foo_elem(bpf_pseudo_fd(table), &key [,&leaf])
bool BTypeVisitor::VisitCallExpr(CallExpr *Call) {
  // make sure node is a reference to a bpf table, which is assured by the
  // presence of the section("maps/<typename>") GNU __attribute__
  if (MemberExpr *Memb = dyn_cast<MemberExpr>(Call->getCallee()->IgnoreImplicit())) {
    StringRef memb_name = Memb->getMemberDecl()->getName();
    if (DeclRefExpr *Ref = dyn_cast<DeclRefExpr>(Memb->getBase())) {
      if (SectionAttr *A = Ref->getDecl()->getAttr<SectionAttr>()) {
        if (!A->getName().startswith("maps"))
          return true;
        // find the table fd, which was opened at declaration time
        auto table_it = tables_.find(Ref->getDecl()->getName());
        if (table_it == tables_.end()) {
          C.getDiagnostics().Report(Ref->getLocEnd(), diag::err_expected)
              << "initialized handle for bpf_table";
          return false;
        }
        string fd = std::to_string(table_it->second.fd);
        string prefix, suffix;
        string map_update_policy = "BPF_ANY";
        if (memb_name == "get") {
          prefix = "bpf_map_lookup_elem_";
          suffix = ")";
        } else if (memb_name == "put") {
          prefix = "bpf_map_update_elem_";
          suffix = ", " + map_update_policy + ")";
        } else if (memb_name == "delete") {
          prefix = "bpf_map_delete_elem_";
          suffix = ")";
        } else {
          llvm::errs() << "error: unknown bpf_table operation " << memb_name << "\n";
          return false;
        }
        prefix += "(bpf_pseudo_fd(1, " + fd + "), ";

        SourceRange argRange(Call->getArg(0)->getLocStart(),
                             Call->getArg(Call->getNumArgs()-1)->getLocEnd());
        string args = rewriter_.getRewrittenText(argRange);
        rewriter_.ReplaceText(SourceRange(Call->getLocStart(), Call->getLocEnd()), prefix + args + suffix);
        return true;
      }
    }
  }
  return true;
}

// look for table subscript references, and turn them into auto table entries:
// table.data[key]
//  becomes:
// struct Key key = {123};
// struct Leaf *leaf = table.get(&key);
// if (!leaf) {
//   struct Leaf zleaf = {0};
//   table.put(&key, &zleaf, BPF_NOEXIST);
//   leaf = table.get(&key);
//   if (!leaf) return -1;
// }
bool BTypeVisitor::VisitArraySubscriptExpr(ArraySubscriptExpr *Arr) {
  Expr *LHS = Arr->getLHS()->IgnoreImplicit();
  Expr *RHS = Arr->getRHS()->IgnoreImplicit();
  if (MemberExpr *Memb = dyn_cast<MemberExpr>(LHS)) {
    if (DeclRefExpr *Ref = dyn_cast<DeclRefExpr>(Memb->getBase())) {
      if (SectionAttr *A = Ref->getDecl()->getAttr<SectionAttr>()) {
        if (A->getName().startswith("maps")) {
          auto table_it = tables_.find(Ref->getDecl()->getName());
          if (table_it == tables_.end()) {
            C.getDiagnostics().Report(Ref->getLocEnd(), diag::err_expected)
                << "initialized handle for bpf_table";
            return false;
          }
          string fd = std::to_string(table_it->second.fd);
          string map_update_policy = "BPF_NOEXIST";
          string name = Ref->getDecl()->getName();
          SourceRange argRange(RHS->getLocStart(), RHS->getLocEnd());
          string args = rewriter_.getRewrittenText(argRange);
          string lookup = "bpf_map_lookup_elem_(bpf_pseudo_fd(1, " + fd + ")";
          string update = "bpf_map_update_elem_(bpf_pseudo_fd(1, " + fd + ")";
          string txt = "(*({typeof(" + name + ".leaf) *leaf = " + lookup + ", " + args + "); ";
          txt         += "if (!leaf) {";
          txt         += " typeof(" + name + ".leaf) zleaf = {0};";
          txt         += " " + update + ", " + args + ", &zleaf, " + map_update_policy + ");";
          txt         += " leaf = " + lookup + ", " + args + ");";
          txt         += " if (!leaf) return -1;";
          txt         += "}";
          txt         += "leaf;}))";
          rewriter_.ReplaceText(SourceRange(Arr->getLocStart(), Arr->getLocEnd()), txt);
        }
      }
    }
  }
  return true;
}

// Open table FDs when bpf tables (as denoted by section("maps*") attribute)
// are declared.
bool BTypeVisitor::VisitVarDecl(VarDecl *Decl) {
  const RecordType *R = Decl->getType()->getAs<RecordType>();
  if (SectionAttr *A = Decl->getAttr<SectionAttr>()) {
    if (!A->getName().startswith("maps"))
      return true;
    if (!R) {
      C.getDiagnostics().Report(Decl->getLocEnd(), diag::err_expected)
          << "struct type for bpf_table";
      return false;
    }
    const RecordDecl *RD = R->getDecl()->getDefinition();
    BPFTable table;
    unsigned i = 0;
    for (auto F : RD->fields()) {
      size_t sz = C.getTypeSize(F->getType()) >> 3;
      if (F->getName() == "key") {
        table.key_size = sz;
      } else if (F->getName() == "leaf") {
        table.leaf_size = sz;
      } else if (F->getName() == "data") {
        table.max_entries = sz / table.leaf_size;
      }
      ++i;
    }
    bpf_map_type map_type = BPF_MAP_TYPE_UNSPEC;
    if (A->getName() == "maps/hash")
      map_type = BPF_MAP_TYPE_HASH;
    else if (A->getName() == "maps/array")
      map_type = BPF_MAP_TYPE_ARRAY;
    table.fd = bpf_create_map(map_type, table.key_size, table.leaf_size, table.max_entries);
    if (table.fd < 0) {
      llvm::errs() << "error: could not open bpf fd\n";
      return false;
    }
    tables_[Decl->getName()] = table;
  }
  return true;
}
bool BTypeVisitor::VisitDeclRefExpr(DeclRefExpr *E) {
  //ValueDecl *D = E->getDecl();
  //BPFTableAttr *A = D->getAttr<BPFTableAttr>();
  return true;
}

BTypeConsumer::BTypeConsumer(ASTContext &C, Rewriter &rewriter, map<string, BPFTable> &tables)
    : visitor_(C, rewriter, tables) {
}

bool BTypeConsumer::HandleTopLevelDecl(DeclGroupRef D) {
  for (auto it : D)
    visitor_.TraverseDecl(it);
  return true;
}

BFrontendAction::BFrontendAction(llvm::raw_ostream &os)
    : rewriter_(new Rewriter), os_(os), tables_(new map<string, BPFTable>) {
}

void BFrontendAction::EndSourceFileAction() {
  // uncomment to see rewritten source
  //rewriter_->getEditBuffer(rewriter_->getSourceMgr().getMainFileID()).write(llvm::errs());
  rewriter_->getEditBuffer(rewriter_->getSourceMgr().getMainFileID()).write(os_);
  os_.flush();
}

unique_ptr<ASTConsumer> BFrontendAction::CreateASTConsumer(CompilerInstance &Compiler, llvm::StringRef InFile) {
  rewriter_->setSourceMgr(Compiler.getSourceManager(), Compiler.getLangOpts());
  return unique_ptr<ASTConsumer>(new BTypeConsumer(Compiler.getASTContext(), *rewriter_, *tables_));
}

}
