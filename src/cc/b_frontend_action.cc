/*
 * Copyright (c) 2015 PLUMgrid, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <linux/bpf.h>
#include <linux/version.h>
#include <sys/utsname.h>

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

const char *calling_conv_regs_x86[] = {
  "di", "si", "dx", "cx", "r8", "r9"
};
// todo: support more archs
const char **calling_conv_regs = calling_conv_regs_x86;

using std::map;
using std::string;
using std::to_string;
using std::unique_ptr;
using std::vector;
using namespace clang;

// Encode the struct layout as a json description
BMapDeclVisitor::BMapDeclVisitor(ASTContext &C, string &result)
    : C(C), result_(result) {}
bool BMapDeclVisitor::VisitFieldDecl(FieldDecl *D) {
  result_ += "\"";
  result_ += D->getName();
  result_ += "\",";
  return true;
}
bool BMapDeclVisitor::VisitRecordDecl(RecordDecl *D) {
  result_ += "[\"";
  result_ += D->getName();
  result_ += "\", [";
  for (auto F : D->getDefinition()->fields()) {
    result_ += "[";
    TraverseDecl(F);
    if (F->isBitField())
      result_ += ", " + to_string(F->getBitWidthValue(C));
    result_ += "], ";
  }
  if (!D->getDefinition()->field_empty())
    result_.erase(result_.end() - 2);
  result_ += "]]";
  return false;
}
bool BMapDeclVisitor::VisitTagType(const TagType *T) {
  return TraverseDecl(T->getDecl()->getDefinition());
}
bool BMapDeclVisitor::VisitTypedefType(const TypedefType *T) {
  return TraverseDecl(T->getDecl());
}
bool BMapDeclVisitor::VisitBuiltinType(const BuiltinType *T) {
  result_ += "\"";
  result_ += T->getName(C.getPrintingPolicy());
  result_ += "\"";
  return true;
}

BTypeVisitor::BTypeVisitor(ASTContext &C, Rewriter &rewriter, map<string, BPFTable> &tables)
    : C(C), rewriter_(rewriter), out_(llvm::errs()), tables_(tables) {
}

bool BTypeVisitor::VisitFunctionDecl(FunctionDecl *D) {
  // put each non-static non-inline function decl in its own section, to be
  // extracted by the MemoryManager
  if (D->isExternallyVisible() && D->hasBody()) {
    string attr = string("__attribute__((section(\".") + D->getName().str() + "\")))\n";
    rewriter_.InsertText(D->getLocStart(), attr);
    // remember the arg names of the current function...first one is the ctx
    fn_args_.clear();
    for (auto arg : D->params()) {
      if (arg->getName() == "") {
        C.getDiagnostics().Report(arg->getLocEnd(), diag::err_expected)
            << "named arguments in BPF program definition";
        return false;
      }
      fn_args_.push_back(arg);
    }
  }
  return true;
}

// Reverse the order of call traversal so that parameters inside of
// function calls will get rewritten before the call itself, otherwise
// text mangling will result.
bool BTypeVisitor::TraverseCallExpr(CallExpr *Call) {
  for (auto child : Call->children())
    if (!TraverseStmt(child))
      return false;
  if (!WalkUpFromCallExpr(Call))
    return false;
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

        SourceRange argRange(Call->getArg(0)->getLocStart(),
                             Call->getArg(Call->getNumArgs()-1)->getLocEnd());
        string args = rewriter_.getRewrittenText(argRange);

        // find the table fd, which was opened at declaration time
        auto table_it = tables_.find(Ref->getDecl()->getName());
        if (table_it == tables_.end()) {
          C.getDiagnostics().Report(Ref->getLocEnd(), diag::err_expected)
              << "initialized handle for bpf_table";
          return false;
        }
        string fd = to_string(table_it->second.fd);
        string prefix, suffix;
        string map_update_policy = "BPF_ANY";
        string txt;
        if (memb_name == "lookup_or_init") {
          string map_update_policy = "BPF_NOEXIST";
          string name = Ref->getDecl()->getName();
          string arg0 = rewriter_.getRewrittenText(SourceRange(Call->getArg(0)->getLocStart(),
                                                               Call->getArg(0)->getLocEnd()));
          string arg1 = rewriter_.getRewrittenText(SourceRange(Call->getArg(1)->getLocStart(),
                                                               Call->getArg(1)->getLocEnd()));
          string lookup = "bpf_map_lookup_elem_(bpf_pseudo_fd(1, " + fd + ")";
          string update = "bpf_map_update_elem_(bpf_pseudo_fd(1, " + fd + ")";
          txt  = "({typeof(" + name + ".leaf) *leaf = " + lookup + ", " + arg0 + "); ";
          txt += "if (!leaf) {";
          txt += " " + update + ", " + arg0 + ", " + arg1 + ", " + map_update_policy + ");";
          txt += " leaf = " + lookup + ", " + arg0 + ");";
          txt += " if (!leaf) return 0;";
          txt += "}";
          txt += "leaf;})";
        } else {
          if (memb_name == "lookup") {
            prefix = "bpf_map_lookup_elem";
            suffix = ")";
          } else if (memb_name == "update") {
            prefix = "bpf_map_update_elem";
            suffix = ", " + map_update_policy + ")";
          } else if (memb_name == "delete") {
            prefix = "bpf_map_delete_elem";
            suffix = ")";
          } else if (memb_name == "call") {
            prefix = "bpf_tail_call_";
            suffix = ")";
          } else {
            llvm::errs() << "error: unknown bpf_table operation " << memb_name << "\n";
            return false;
          }
          prefix += "((void *)bpf_pseudo_fd(1, " + fd + "), ";

          txt = prefix + args + suffix;
        }
        if (!rewriter_.isRewritable(Call->getLocStart())) {
          C.getDiagnostics().Report(Call->getLocStart(), diag::err_expected)
              << "use of map function not in a macro";
          return false;
        }
        rewriter_.ReplaceText(SourceRange(Call->getLocStart(), Call->getLocEnd()), txt);
        return true;
      }
    }
  } else if (Call->getCalleeDecl()) {
    NamedDecl *Decl = dyn_cast<NamedDecl>(Call->getCalleeDecl());
    if (!Decl) return true;
    if (AsmLabelAttr *A = Decl->getAttr<AsmLabelAttr>()) {
      // Functions with the tag asm("llvm.bpf.extra") are implemented in the
      // rewriter rather than as a macro since they may also include nested
      // rewrites, and clang::Rewriter does not support rewrites in macros,
      // unless one preprocesses the entire source file.
      if (A->getLabel() == "llvm.bpf.extra") {
        if (!rewriter_.isRewritable(Call->getLocStart())) {
          C.getDiagnostics().Report(Call->getLocStart(), diag::err_expected)
              << "use of extra builtin not in a macro";
          return false;
        }

        vector<string> args;
        for (auto arg : Call->arguments())
          args.push_back(rewriter_.getRewrittenText(SourceRange(arg->getLocStart(), arg->getLocEnd())));

        string text;
        if (Decl->getName() == "incr_cksum_l3") {
          text = "bpf_l3_csum_replace_(" + fn_args_[0]->getName().str() + ", (u64)";
          text += args[0] + ", " + args[1] + ", " + args[2] + ", sizeof(" + args[2] + "))";
        } else if (Decl->getName() == "incr_cksum_l4") {
          text = "bpf_l4_csum_replace_(" + fn_args_[0]->getName().str() + ", (u64)";
          text += args[0] + ", " + args[1] + ", " + args[2];
          text += ", ((" + args[3] + " & 0x1) << 4) | sizeof(" + args[2] + "))";
        } else if (Decl->getName() == "bpf_trace_printk") {
          //  #define bpf_trace_printk(fmt, args...)
          //    ({ char _fmt[] = fmt; bpf_trace_printk_(_fmt, sizeof(_fmt), args...); })
          text = "({ char _fmt[] = " + args[0] + "; bpf_trace_printk_(_fmt, sizeof(_fmt)";
          if (args.size() > 1)
            text += ", ";
          for (auto arg = args.begin() + 1; arg != args.end(); ++arg) {
            text += *arg;
            if (arg + 1 != args.end())
              text += ", ";
          }
          text += "); })";
        }
        rewriter_.ReplaceText(SourceRange(Call->getLocStart(), Call->getLocEnd()), text);
      }
    }
  }
  return true;
}

bool BTypeVisitor::TraverseMemberExpr(MemberExpr *E) {
  for (auto child : E->children())
    if (!TraverseStmt(child))
      return false;
  if (!WalkUpFromMemberExpr(E))
    return false;
  return true;
}

bool BTypeVisitor::VisitMemberExpr(MemberExpr *E) {
  if (DeclRefExpr *Ref = dyn_cast<DeclRefExpr>(E->getBase()->IgnoreImplicit())) {
    auto it = std::find(fn_args_.begin() + 1, fn_args_.end(), Ref->getDecl());
    if (it != fn_args_.end()) {
      FieldDecl *F = dyn_cast<FieldDecl>(E->getMemberDecl());
      string base_type = Ref->getType()->getPointeeType().getAsString();
      string pre, post;
      pre = "({ " + E->getType().getAsString() + " _val; memset(&_val, 0, sizeof(_val));";
      pre += " bpf_probe_read(&_val, sizeof(_val), ";
      post = " + offsetof(" + base_type + ", " + F->getName().str() + ")";
      post += "); _val; })";
      rewriter_.InsertText(E->getLocStart(), pre);
      rewriter_.ReplaceText(SourceRange(E->getOperatorLoc(), E->getLocEnd()), post);
    }
  }
  return true;
}

bool BTypeVisitor::VisitDeclRefExpr(DeclRefExpr *E) {
  auto it = std::find(fn_args_.begin() + 1, fn_args_.end(), E->getDecl());
  if (it != fn_args_.end()) {
    if (!rewriter_.isRewritable(E->getLocStart())) {
      C.getDiagnostics().Report(E->getLocStart(), diag::err_expected)
          << "use of probe argument not in a macro";
      return false;
    }
    size_t d = std::distance(fn_args_.begin() + 1, it);
    const char *reg = calling_conv_regs[d];
    string text = "((u64)" + fn_args_[0]->getName().str() + "->" + string(reg) + ")";
    rewriter_.ReplaceText(SourceRange(E->getLocStart(), E->getLocEnd()), text);
    return true;
  }
  return true;
}

bool BTypeVisitor::VisitBinaryOperator(BinaryOperator *E) {
  if (!E->isAssignmentOp())
    return true;
  Expr *LHS = E->getLHS()->IgnoreImplicit();
  Expr *RHS = E->getRHS()->IgnoreImplicit();
  if (MemberExpr *Memb = dyn_cast<MemberExpr>(LHS)) {
    if (DeclRefExpr *Base = dyn_cast<DeclRefExpr>(Memb->getBase()->IgnoreImplicit())) {
      if (DeprecatedAttr *A = Base->getDecl()->getAttr<DeprecatedAttr>()) {
        if (A->getMessage() == "packet") {
          if (FieldDecl *F = dyn_cast<FieldDecl>(Memb->getMemberDecl())) {
            if (!rewriter_.isRewritable(E->getLocStart())) {
              C.getDiagnostics().Report(E->getLocStart(), diag::err_expected)
                  << "use of \"packet\" header type not in a macro";
              return false;
            }
            uint64_t ofs = C.getFieldOffset(F);
            uint64_t sz = F->isBitField() ? F->getBitWidthValue(C) : C.getTypeSize(F->getType());
            string base = rewriter_.getRewrittenText(SourceRange(Base->getLocStart(), Base->getLocEnd()));
            string rhs = rewriter_.getRewrittenText(SourceRange(RHS->getLocStart(), RHS->getLocEnd()));
            string text = "bpf_dins_pkt(" + fn_args_[0]->getName().str() + ", (u64)" + base + "+" + to_string(ofs >> 3)
                + ", " + to_string(ofs & 0x7) + ", " + to_string(sz) + ", " + rhs + ")";
            rewriter_.ReplaceText(SourceRange(E->getLocStart(), E->getLocEnd()), text);
          }
        }
      }
    }
  }
  return true;
}
bool BTypeVisitor::VisitImplicitCastExpr(ImplicitCastExpr *E) {
  // use dext only for RValues
  if (E->getCastKind() != CK_LValueToRValue)
    return true;
  MemberExpr *Memb = dyn_cast<MemberExpr>(E->IgnoreImplicit());
  if (!Memb)
    return true;
  Expr *Base = Memb->getBase()->IgnoreImplicit();
  if (DeclRefExpr *Ref = dyn_cast<DeclRefExpr>(Base)) {
    if (DeprecatedAttr *A = Ref->getDecl()->getAttr<DeprecatedAttr>()) {
      if (A->getMessage() == "packet") {
        if (FieldDecl *F = dyn_cast<FieldDecl>(Memb->getMemberDecl())) {
          if (!rewriter_.isRewritable(E->getLocStart())) {
            C.getDiagnostics().Report(E->getLocStart(), diag::err_expected)
                << "use of \"packet\" header type not in a macro";
            return false;
          }
          uint64_t ofs = C.getFieldOffset(F);
          uint64_t sz = F->isBitField() ? F->getBitWidthValue(C) : C.getTypeSize(F->getType());
          string text = "bpf_dext_pkt(" + fn_args_[0]->getName().str() + ", (u64)" + Ref->getDecl()->getName().str() + "+"
              + to_string(ofs >> 3) + ", " + to_string(ofs & 0x7) + ", " + to_string(sz) + ")";
          rewriter_.ReplaceText(SourceRange(E->getLocStart(), E->getLocEnd()), text);
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
        BMapDeclVisitor visitor(C, table.key_desc);
        visitor.TraverseType(F->getType());
      } else if (F->getName() == "leaf") {
        table.leaf_size = sz;
        BMapDeclVisitor visitor(C, table.leaf_desc);
        visitor.TraverseType(F->getType());
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
    else if (A->getName() == "maps/prog") {
      struct utsname un;
      if (uname(&un) == 0) {
        int major = 0, minor = 0;
        // release format: <major>.<minor>.<revision>[-<othertag>]
        sscanf(un.release, "%d.%d.", &major, &minor);
        if (KERNEL_VERSION(major,minor,0) >= KERNEL_VERSION(4,2,0))
          map_type = BPF_MAP_TYPE_PROG_ARRAY;
      }
      if (map_type == BPF_MAP_TYPE_UNSPEC) {
        llvm::errs() << "error: maps/prog is not supported\n";
        return false;
      }
    }
    table.fd = bpf_create_map(map_type, table.key_size, table.leaf_size, table.max_entries);
    if (table.fd < 0) {
      llvm::errs() << "error: could not open bpf fd\n";
      return false;
    }
    tables_[Decl->getName()] = std::move(table);
  } else if (const PointerType *P = Decl->getType()->getAs<PointerType>()) {
    // if var is a pointer to a packet type, clone the annotation into the var
    // decl so that the packet dext/dins rewriter can catch it
    if (const RecordType *RT = P->getPointeeType()->getAs<RecordType>()) {
      if (const RecordDecl *RD = RT->getDecl()->getDefinition()) {
        if (DeprecatedAttr *DA = RD->getAttr<DeprecatedAttr>()) {
          if (DA->getMessage() == "packet") {
            Decl->addAttr(DA->clone(C));
          }
        }
      }
    }
  }
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
