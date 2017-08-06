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
#include <unistd.h>

#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/RecordLayout.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/MultiplexConsumer.h>
#include <clang/Rewrite/Core/Rewriter.h>

#include "b_frontend_action.h"
#include "loader.h"
#include "common.h"
#include "table_storage.h"

#include "libbpf.h"

namespace ebpf {

constexpr int MAX_CALLING_CONV_REGS = 6;
const char *calling_conv_regs_x86[] = {
  "di", "si", "dx", "cx", "r8", "r9"
};
const char *calling_conv_regs_ppc[] = {"gpr[3]", "gpr[4]", "gpr[5]",
                                       "gpr[6]", "gpr[7]", "gpr[8]"};

const char *calling_conv_regs_s390x[] = {"gprs[2]", "gprs[3]", "gprs[4]",
					 "gprs[5]", "gprs[6]" };

const char *calling_conv_regs_arm64[] = {"regs[0]", "regs[1]", "regs[2]",
                                       "regs[3]", "regs[4]", "regs[5]"};
// todo: support more archs
#if defined(__powerpc__)
const char **calling_conv_regs = calling_conv_regs_ppc;
#elif defined(__s390x__)
const char **calling_conv_regs = calling_conv_regs_s390x;
#elif defined(__aarch64__)
const char **calling_conv_regs = calling_conv_regs_arm64;
#else
const char **calling_conv_regs = calling_conv_regs_x86;
#endif

using std::map;
using std::move;
using std::set;
using std::string;
using std::to_string;
using std::unique_ptr;
using std::vector;
using namespace clang;

class ProbeChecker : public RecursiveASTVisitor<ProbeChecker> {
 public:
  explicit ProbeChecker(Expr *arg, const set<Decl *> &ptregs)
      : needs_probe_(false), is_transitive_(false), ptregs_(ptregs) {
    if (arg) {
      TraverseStmt(arg);
      if (arg->getType()->isPointerType())
        is_transitive_ = needs_probe_;
    }
  }
  bool VisitCallExpr(CallExpr *E) {
    needs_probe_ = false;
    if (VarDecl *V = dyn_cast<VarDecl>(E->getCalleeDecl())) {
      needs_probe_ = V->getName() == "bpf_get_current_task";
    }
    return false;
  }
  bool VisitDeclRefExpr(DeclRefExpr *E) {
    if (ptregs_.find(E->getDecl()) != ptregs_.end())
      needs_probe_ = true;
    return true;
  }
  bool needs_probe() const { return needs_probe_; }
  bool is_transitive() const { return is_transitive_; }
 private:
  bool needs_probe_;
  bool is_transitive_;
  const set<Decl *> &ptregs_;
};

// Visit a piece of the AST and mark it as needing probe reads
class ProbeSetter : public RecursiveASTVisitor<ProbeSetter> {
 public:
  explicit ProbeSetter(set<Decl *> *ptregs) : ptregs_(ptregs) {}
  bool VisitDeclRefExpr(DeclRefExpr *E) {
    ptregs_->insert(E->getDecl());
    return true;
  }
 private:
  set<Decl *> *ptregs_;
};

ProbeVisitor::ProbeVisitor(ASTContext &C, Rewriter &rewriter) : C(C), rewriter_(rewriter) {}

bool ProbeVisitor::VisitVarDecl(VarDecl *Decl) {
  if (Expr *E = Decl->getInit()) {
    if (ProbeChecker(E, ptregs_).is_transitive())
      set_ptreg(Decl);
  }
  return true;
}
bool ProbeVisitor::VisitCallExpr(CallExpr *Call) {
  if (FunctionDecl *F = dyn_cast<FunctionDecl>(Call->getCalleeDecl())) {
    if (F->hasBody()) {
      unsigned i = 0;
      for (auto arg : Call->arguments()) {
        if (ProbeChecker(arg, ptregs_).needs_probe())
          ptregs_.insert(F->getParamDecl(i));
        ++i;
      }
      if (fn_visited_.find(F) == fn_visited_.end()) {
        fn_visited_.insert(F);
        TraverseDecl(F);
      }
    }
  }
  return true;
}
bool ProbeVisitor::VisitBinaryOperator(BinaryOperator *E) {
  if (!E->isAssignmentOp())
    return true;
  // copy probe attribute from RHS to LHS if present
  if (ProbeChecker(E->getRHS(), ptregs_).is_transitive()) {
    ProbeSetter setter(&ptregs_);
    setter.TraverseStmt(E->getLHS());
  }
  return true;
}
bool ProbeVisitor::VisitUnaryOperator(UnaryOperator *E) {
  if (E->getOpcode() != UO_Deref)
    return true;
  if (memb_visited_.find(E) != memb_visited_.end())
    return true;
  if (!ProbeChecker(E, ptregs_).needs_probe())
    return true;
  memb_visited_.insert(E);
  Expr *sub = E->getSubExpr();
  string rhs = rewriter_.getRewrittenText(expansionRange(sub->getSourceRange()));
  string text;
  text = "({ typeof(" + E->getType().getAsString() + ") _val; memset(&_val, 0, sizeof(_val));";
  text += " bpf_probe_read(&_val, sizeof(_val), (u64)";
  text += rhs + "); _val; })";
  rewriter_.ReplaceText(expansionRange(E->getSourceRange()), text);
  return true;
}
bool ProbeVisitor::VisitMemberExpr(MemberExpr *E) {
  if (memb_visited_.find(E) != memb_visited_.end()) return true;

  // Checks to see if the expression references something that needs to be run
  // through bpf_probe_read.
  if (!ProbeChecker(E, ptregs_).needs_probe())
    return true;

  Expr *base;
  SourceLocation rhs_start, op;
  bool found = false;
  for (MemberExpr *M = E; M; M = dyn_cast<MemberExpr>(M->getBase())) {
    memb_visited_.insert(M);
    rhs_start = M->getLocEnd();
    base = M->getBase();
    op = M->getOperatorLoc();
    if (M->isArrow()) {
      found = true;
      break;
    }
  }
  if (!found)
    return true;
  if (op.isInvalid()) {
    error(base->getLocEnd(), "internal error: opLoc is invalid while preparing probe rewrite");
    return false;
  }
  string rhs = rewriter_.getRewrittenText(expansionRange(SourceRange(rhs_start, E->getLocEnd())));
  string base_type = base->getType()->getPointeeType().getAsString();
  string pre, post;
  pre = "({ typeof(" + E->getType().getAsString() + ") _val; memset(&_val, 0, sizeof(_val));";
  pre += " bpf_probe_read(&_val, sizeof(_val), (u64)";
  post = " + offsetof(" + base_type + ", " + rhs + ")";
  post += "); _val; })";
  rewriter_.InsertText(E->getLocStart(), pre);
  rewriter_.ReplaceText(expansionRange(SourceRange(op, E->getLocEnd())), post);
  return true;
}

SourceRange
ProbeVisitor::expansionRange(SourceRange range) {
  return rewriter_.getSourceMgr().getExpansionRange(range);
}

template <unsigned N>
DiagnosticBuilder ProbeVisitor::error(SourceLocation loc, const char (&fmt)[N]) {
  unsigned int diag_id = C.getDiagnostics().getCustomDiagID(DiagnosticsEngine::Error, fmt);
  return C.getDiagnostics().Report(loc, diag_id);
}

BTypeVisitor::BTypeVisitor(ASTContext &C, BFrontendAction &fe)
    : C(C), diag_(C.getDiagnostics()), fe_(fe), rewriter_(fe.rewriter()), out_(llvm::errs()) {}

bool BTypeVisitor::VisitFunctionDecl(FunctionDecl *D) {
  // put each non-static non-inline function decl in its own section, to be
  // extracted by the MemoryManager
  auto real_start_loc = rewriter_.getSourceMgr().getFileLoc(D->getLocStart());
  if (D->isExternallyVisible() && D->hasBody()) {
    current_fn_ = D->getName();
    string bd = rewriter_.getRewrittenText(expansionRange(D->getSourceRange()));
    fe_.func_src_.set_src(current_fn_, bd);
    fe_.func_range_[current_fn_] = expansionRange(D->getSourceRange());
    string attr = string("__attribute__((section(\"") + BPF_FN_PREFIX + D->getName().str() + "\")))\n";
    rewriter_.InsertText(real_start_loc, attr);
    if (D->param_size() > MAX_CALLING_CONV_REGS + 1) {
      error(D->getParamDecl(MAX_CALLING_CONV_REGS + 1)->getLocStart(),
            "too many arguments, bcc only supports in-register parameters");
      return false;
    }
    // remember the arg names of the current function...first one is the ctx
    fn_args_.clear();
    string preamble = "{";
    for (auto arg_it = D->param_begin(); arg_it != D->param_end(); arg_it++) {
      auto arg = *arg_it;
      if (arg->getName() == "") {
        error(arg->getLocEnd(), "arguments to BPF program definition must be named");
        return false;
      }
      fn_args_.push_back(arg);
      if (fn_args_.size() > 1) {
        // Move the args into a preamble section where the same params are
        // declared and initialized from pt_regs.
        // Todo: this init should be done only when the program requests it.
        string text = rewriter_.getRewrittenText(expansionRange(arg->getSourceRange()));
        arg->addAttr(UnavailableAttr::CreateImplicit(C, "ptregs"));
        size_t d = fn_args_.size() - 2;
        const char *reg = calling_conv_regs[d];
        preamble += " " + text + " = " + fn_args_[0]->getName().str() + "->" +
                    string(reg) + ";";
      }
    }
    if (D->param_size() > 1) {
      rewriter_.ReplaceText(
          expansionRange(SourceRange(D->getParamDecl(0)->getLocEnd(),
                      D->getParamDecl(D->getNumParams() - 1)->getLocEnd())),
          fn_args_[0]->getName());
    }
    // for each trace argument, convert the variable from ptregs to something on stack
    if (CompoundStmt *S = dyn_cast<CompoundStmt>(D->getBody()))
      rewriter_.ReplaceText(S->getLBracLoc(), 1, preamble);
  } else if (D->hasBody() &&
             rewriter_.getSourceMgr().getFileID(real_start_loc)
               == rewriter_.getSourceMgr().getMainFileID()) {
    // rewritable functions that are static should be always treated as helper
    rewriter_.InsertText(real_start_loc, "__attribute__((always_inline))\n");
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

        string args = rewriter_.getRewrittenText(expansionRange(SourceRange(Call->getArg(0)->getLocStart(),
                                                   Call->getArg(Call->getNumArgs() - 1)->getLocEnd())));

        // find the table fd, which was opened at declaration time
        TableStorage::iterator desc;
        Path local_path({fe_.id(), Ref->getDecl()->getName()});
        Path global_path({Ref->getDecl()->getName()});
        if (!fe_.table_storage().Find(local_path, desc)) {
          if (!fe_.table_storage().Find(global_path, desc)) {
            error(Ref->getLocEnd(), "bpf_table %0 failed to open") << Ref->getDecl()->getName();
            return false;
          }
        }
        string fd = to_string(desc->second.fd);
        string prefix, suffix;
        string txt;
        auto rewrite_start = Call->getLocStart();
        auto rewrite_end = Call->getLocEnd();
        if (memb_name == "lookup_or_init") {
          string name = Ref->getDecl()->getName();
          string arg0 = rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));
          string arg1 = rewriter_.getRewrittenText(expansionRange(Call->getArg(1)->getSourceRange()));
          string lookup = "bpf_map_lookup_elem_(bpf_pseudo_fd(1, " + fd + ")";
          string update = "bpf_map_update_elem_(bpf_pseudo_fd(1, " + fd + ")";
          txt  = "({typeof(" + name + ".leaf) *leaf = " + lookup + ", " + arg0 + "); ";
          txt += "if (!leaf) {";
          txt += " " + update + ", " + arg0 + ", " + arg1 + ", BPF_NOEXIST);";
          txt += " leaf = " + lookup + ", " + arg0 + ");";
          txt += " if (!leaf) return 0;";
          txt += "}";
          txt += "leaf;})";
        } else if (memb_name == "increment") {
          string name = Ref->getDecl()->getName();
          string arg0 = rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));
          string lookup = "bpf_map_lookup_elem_(bpf_pseudo_fd(1, " + fd + ")";
          string update = "bpf_map_update_elem_(bpf_pseudo_fd(1, " + fd + ")";
          txt  = "({ typeof(" + name + ".key) _key = " + arg0 + "; ";
          txt += "typeof(" + name + ".leaf) *_leaf = " + lookup + ", &_key); ";
          txt += "if (_leaf) (*_leaf)++; ";
          if (desc->second.type == BPF_MAP_TYPE_HASH) {
            txt += "else { typeof(" + name + ".leaf) _zleaf; memset(&_zleaf, 0, sizeof(_zleaf)); ";
            txt += "_zleaf++; ";
            txt += update + ", &_key, &_zleaf, BPF_NOEXIST); } ";
          }
          txt += "})";
        } else if (memb_name == "perf_submit") {
          string name = Ref->getDecl()->getName();
          string arg0 = rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));
          string args_other = rewriter_.getRewrittenText(expansionRange(SourceRange(Call->getArg(1)->getLocStart(),
                                                           Call->getArg(2)->getLocEnd())));
          txt = "bpf_perf_event_output(" + arg0 + ", bpf_pseudo_fd(1, " + fd + ")";
          txt += ", CUR_CPU_IDENTIFIER, " + args_other + ")";
        } else if (memb_name == "perf_submit_skb") {
          string skb = rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));
          string skb_len = rewriter_.getRewrittenText(expansionRange(Call->getArg(1)->getSourceRange()));
          string meta = rewriter_.getRewrittenText(expansionRange(Call->getArg(2)->getSourceRange()));
          string meta_len = rewriter_.getRewrittenText(expansionRange(Call->getArg(3)->getSourceRange()));
          txt = "bpf_perf_event_output(" +
            skb + ", " +
            "bpf_pseudo_fd(1, " + fd + "), " +
            "((__u64)" + skb_len + " << 32) | BPF_F_CURRENT_CPU, " +
            meta + ", " +
            meta_len + ");";
        } else if (memb_name == "get_stackid") {
          if (desc->second.type == BPF_MAP_TYPE_STACK_TRACE) {
            string arg0 =
                rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));
            txt = "bpf_get_stackid(";
            txt += "bpf_pseudo_fd(1, " + fd + "), " + arg0;
            rewrite_end = Call->getArg(0)->getLocEnd();
            } else {
              error(Call->getLocStart(), "get_stackid only available on stacktrace maps");
              return false;
            }
        } else {
          if (memb_name == "lookup") {
            prefix = "bpf_map_lookup_elem";
            suffix = ")";
          } else if (memb_name == "update") {
            prefix = "bpf_map_update_elem";
            suffix = ", BPF_ANY)";
          } else if (memb_name == "insert") {
            if (desc->second.type == BPF_MAP_TYPE_ARRAY) {
              warning(Call->getLocStart(), "all element of an array already exist; insert() will have no effect");
            }
            prefix = "bpf_map_update_elem";
            suffix = ", BPF_NOEXIST)";
          } else if (memb_name == "delete") {
            prefix = "bpf_map_delete_elem";
            suffix = ")";
          } else if (memb_name == "call") {
            prefix = "bpf_tail_call_";
            suffix = ")";
          } else if (memb_name == "perf_read") {
            prefix = "bpf_perf_event_read";
            suffix = ")";
          } else {
            error(Call->getLocStart(), "invalid bpf_table operation %0") << memb_name;
            return false;
          }
          prefix += "((void *)bpf_pseudo_fd(1, " + fd + "), ";

          txt = prefix + args + suffix;
        }
        if (!rewriter_.isRewritable(rewrite_start) || !rewriter_.isRewritable(rewrite_end)) {
          error(Call->getLocStart(), "cannot use map function inside a macro");
          return false;
        }
        rewriter_.ReplaceText(expansionRange(SourceRange(rewrite_start, rewrite_end)), txt);
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
          error(Call->getLocStart(), "cannot use builtin inside a macro");
          return false;
        }

        vector<string> args;
        for (auto arg : Call->arguments())
          args.push_back(rewriter_.getRewrittenText(expansionRange(arg->getSourceRange())));

        string text;
        if (Decl->getName() == "incr_cksum_l3") {
          text = "bpf_l3_csum_replace_(" + fn_args_[0]->getName().str() + ", (u64)";
          text += args[0] + ", " + args[1] + ", " + args[2] + ", sizeof(" + args[2] + "))";
          rewriter_.ReplaceText(expansionRange(Call->getSourceRange()), text);
        } else if (Decl->getName() == "incr_cksum_l4") {
          text = "bpf_l4_csum_replace_(" + fn_args_[0]->getName().str() + ", (u64)";
          text += args[0] + ", " + args[1] + ", " + args[2];
          text += ", ((" + args[3] + " & 0x1) << 4) | sizeof(" + args[2] + "))";
          rewriter_.ReplaceText(expansionRange(Call->getSourceRange()), text);
        } else if (Decl->getName() == "bpf_trace_printk") {
          checkFormatSpecifiers(args[0], Call->getArg(0)->getLocStart());
          //  #define bpf_trace_printk(fmt, args...)
          //    ({ char _fmt[] = fmt; bpf_trace_printk_(_fmt, sizeof(_fmt), args...); })
          text = "({ char _fmt[] = " + args[0] + "; bpf_trace_printk_(_fmt, sizeof(_fmt)";
          if (args.size() <= 1) {
            text += "); })";
            rewriter_.ReplaceText(expansionRange(Call->getSourceRange()), text);
          } else {
            rewriter_.ReplaceText(expansionRange(SourceRange(Call->getLocStart(), Call->getArg(0)->getLocEnd())), text);
            rewriter_.InsertTextAfter(Call->getLocEnd(), "); }");
          }
        } else if (Decl->getName() == "bpf_num_cpus") {
          int numcpu = sysconf(_SC_NPROCESSORS_ONLN);
          if (numcpu <= 0)
            numcpu = 1;
          text = to_string(numcpu);
          rewriter_.ReplaceText(expansionRange(Call->getSourceRange()), text);
        } else if (Decl->getName() == "bpf_usdt_readarg_p") {
          text = "({ u64 __addr = 0x0; ";
          text += "_bpf_readarg_" + current_fn_ + "_" + args[0] + "(" +
                  args[1] + ", &__addr, sizeof(__addr));";
          text += "bpf_probe_read(" + args[2] + ", " + args[3] +
                  ", (void *)__addr);";
          text += "})";
          rewriter_.ReplaceText(expansionRange(Call->getSourceRange()), text);
        } else if (Decl->getName() == "bpf_usdt_readarg") {
          text = "_bpf_readarg_" + current_fn_ + "_" + args[0] + "(" + args[1] +
                 ", " + args[2] + ", sizeof(*(" + args[2] + ")))";
          rewriter_.ReplaceText(expansionRange(Call->getSourceRange()), text);
        }
      }
    } else if (FunctionDecl *F = dyn_cast<FunctionDecl>(Decl)) {
      if (F->isExternallyVisible() && !F->getBuiltinID()) {
        auto start_loc = rewriter_.getSourceMgr().getFileLoc(Decl->getLocStart());
        if (rewriter_.getSourceMgr().getFileID(start_loc)
            == rewriter_.getSourceMgr().getMainFileID()) {
          error(Call->getLocStart(), "cannot call non-static helper function");
          return false;
        }
      }
    }
  }
  return true;
}

bool BTypeVisitor::checkFormatSpecifiers(const string& fmt, SourceLocation loc) {
  unsigned nb_specifiers = 0, i, j;
  bool has_s = false;
  for (i = 0; i < fmt.length(); i++) {
    if (!isascii(fmt[i]) || (!isprint(fmt[i]) && !isspace(fmt[i]))) {
      warning(loc.getLocWithOffset(i), "unrecognized character");
      return false;
    }
    if (fmt[i] != '%')
      continue;
    if (nb_specifiers >= 3) {
      warning(loc.getLocWithOffset(i), "cannot use more than 3 conversion specifiers");
      return false;
    }
    nb_specifiers++;
    i++;
    if (fmt[i] == 'l') {
      i++;
    } else if (fmt[i] == 'p' || fmt[i] == 's') {
      i++;
      if (!isspace(fmt[i]) && !ispunct(fmt[i]) && fmt[i] != 0) {
        warning(loc.getLocWithOffset(i - 2),
                "only %%d %%u %%x %%ld %%lu %%lx %%lld %%llu %%llx %%p %%s conversion specifiers allowed");
        return false;
      }
      if (fmt[i - 1] == 's') {
        if (has_s) {
          warning(loc.getLocWithOffset(i - 2), "cannot use several %%s conversion specifiers");
          return false;
        }
        has_s = true;
      }
      continue;
    }
    j = 1;
    if (fmt[i] == 'l') {
      i++;
      j++;
    }
    if (fmt[i] != 'd' && fmt[i] != 'u' && fmt[i] != 'x') {
      warning(loc.getLocWithOffset(i - j),
              "only %%d %%u %%x %%ld %%lu %%lx %%lld %%llu %%llx %%p %%s conversion specifiers allowed");
      return false;
    }
  }
  return true;
}

bool BTypeVisitor::VisitBinaryOperator(BinaryOperator *E) {
  if (!E->isAssignmentOp())
    return true;
  Expr *LHS = E->getLHS()->IgnoreImplicit();
  if (MemberExpr *Memb = dyn_cast<MemberExpr>(LHS)) {
    if (DeclRefExpr *Base = dyn_cast<DeclRefExpr>(Memb->getBase()->IgnoreImplicit())) {
      if (DeprecatedAttr *A = Base->getDecl()->getAttr<DeprecatedAttr>()) {
        if (A->getMessage() == "packet") {
          if (FieldDecl *F = dyn_cast<FieldDecl>(Memb->getMemberDecl())) {
            if (!rewriter_.isRewritable(E->getLocStart())) {
              error(E->getLocStart(), "cannot use \"packet\" header type inside a macro");
              return false;
            }
            uint64_t ofs = C.getFieldOffset(F);
            uint64_t sz = F->isBitField() ? F->getBitWidthValue(C) : C.getTypeSize(F->getType());
            string base = rewriter_.getRewrittenText(expansionRange(Base->getSourceRange()));
            string text = "bpf_dins_pkt(" + fn_args_[0]->getName().str() + ", (u64)" + base + "+" + to_string(ofs >> 3)
                + ", " + to_string(ofs & 0x7) + ", " + to_string(sz) + ",";
            rewriter_.ReplaceText(expansionRange(SourceRange(E->getLocStart(), E->getOperatorLoc())), text);
            rewriter_.InsertTextAfterToken(E->getLocEnd(), ")");
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
            error(E->getLocStart(), "cannot use \"packet\" header type inside a macro");
            return false;
          }
          uint64_t ofs = C.getFieldOffset(F);
          uint64_t sz = F->isBitField() ? F->getBitWidthValue(C) : C.getTypeSize(F->getType());
          string text = "bpf_dext_pkt(" + fn_args_[0]->getName().str() + ", (u64)" + Ref->getDecl()->getName().str() + "+"
              + to_string(ofs >> 3) + ", " + to_string(ofs & 0x7) + ", " + to_string(sz) + ")";
          rewriter_.ReplaceText(expansionRange(E->getSourceRange()), text);
        }
      }
    }
  }
  return true;
}

SourceRange
BTypeVisitor::expansionRange(SourceRange range) {
  return rewriter_.getSourceMgr().getExpansionRange(range);
}

template <unsigned N>
DiagnosticBuilder BTypeVisitor::error(SourceLocation loc, const char (&fmt)[N]) {
  unsigned int diag_id = C.getDiagnostics().getCustomDiagID(DiagnosticsEngine::Error, fmt);
  return C.getDiagnostics().Report(loc, diag_id);
}

template <unsigned N>
DiagnosticBuilder BTypeVisitor::warning(SourceLocation loc, const char (&fmt)[N]) {
  unsigned int diag_id = C.getDiagnostics().getCustomDiagID(DiagnosticsEngine::Warning, fmt);
  return C.getDiagnostics().Report(loc, diag_id);
}

// Open table FDs when bpf tables (as denoted by section("maps*") attribute)
// are declared.
bool BTypeVisitor::VisitVarDecl(VarDecl *Decl) {
  const RecordType *R = Decl->getType()->getAs<RecordType>();
  if (SectionAttr *A = Decl->getAttr<SectionAttr>()) {
    if (!A->getName().startswith("maps"))
      return true;
    if (!R) {
      error(Decl->getLocEnd(), "invalid type for bpf_table, expect struct");
      return false;
    }
    const RecordDecl *RD = R->getDecl()->getDefinition();

    TableDesc table;
    TableStorage::iterator table_it;
    table.name = Decl->getName();
    Path local_path({fe_.id(), table.name});
    Path global_path({table.name});
    QualType key_type, leaf_type;

    unsigned i = 0;
    for (auto F : RD->fields()) {
      if (F->getType().getTypePtr()->isIncompleteType()) {
        error(F->getLocStart(), "unknown type");
        return false;
      }

      size_t sz = C.getTypeSize(F->getType()) >> 3;
      if (F->getName() == "key") {
        if (sz == 0) {
          error(F->getLocStart(), "invalid zero-sized leaf");
          return false;
        }
        table.key_size = sz;
        key_type = F->getType();
      } else if (F->getName() == "leaf") {
        if (sz == 0) {
          error(F->getLocStart(), "invalid zero-sized leaf");
          return false;
        }
        table.leaf_size = sz;
        leaf_type = F->getType();
      } else if (F->getName() == "max_entries") {
        unsigned idx = F->getFieldIndex();
        if (auto I = dyn_cast_or_null<InitListExpr>(Decl->getInit())) {
          llvm::APSInt res;
          if (I->getInit(idx)->EvaluateAsInt(res, C)) {
            table.max_entries = res.getExtValue();
          }
        }
      } else if (F->getName() == "flags") {
        unsigned idx = F->getFieldIndex();
        if (auto I = dyn_cast_or_null<InitListExpr>(Decl->getInit())) {
          llvm::APSInt res;
          if (I->getInit(idx)->EvaluateAsInt(res, C)) {
            table.flags = res.getExtValue();
          }
        }
      }
      ++i;
    }

    bpf_map_type map_type = BPF_MAP_TYPE_UNSPEC;
    if (A->getName() == "maps/hash") {
      map_type = BPF_MAP_TYPE_HASH;
    } else if (A->getName() == "maps/array") {
      map_type = BPF_MAP_TYPE_ARRAY;
    } else if (A->getName() == "maps/percpu_hash") {
      map_type = BPF_MAP_TYPE_PERCPU_HASH;
    } else if (A->getName() == "maps/percpu_array") {
      map_type = BPF_MAP_TYPE_PERCPU_ARRAY;
    } else if (A->getName() == "maps/lru_hash") {
      map_type = BPF_MAP_TYPE_LRU_HASH;
    } else if (A->getName() == "maps/lru_percpu_hash") {
      map_type = BPF_MAP_TYPE_LRU_PERCPU_HASH;
    } else if (A->getName() == "maps/lpm_trie") {
      map_type = BPF_MAP_TYPE_LPM_TRIE;
    } else if (A->getName() == "maps/histogram") {
      map_type = BPF_MAP_TYPE_HASH;
      if (key_type->isSpecificBuiltinType(BuiltinType::Int))
        map_type = BPF_MAP_TYPE_ARRAY;
      if (!leaf_type->isSpecificBuiltinType(BuiltinType::ULongLong))
        error(Decl->getLocStart(), "histogram leaf type must be u64, got %0") << leaf_type;
    } else if (A->getName() == "maps/prog") {
      map_type = BPF_MAP_TYPE_PROG_ARRAY;
    } else if (A->getName() == "maps/perf_output") {
      map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
      int numcpu = get_possible_cpus().size();
      if (numcpu <= 0)
        numcpu = 1;
      table.max_entries = numcpu;
    } else if (A->getName() == "maps/perf_array") {
      map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
    } else if (A->getName() == "maps/stacktrace") {
      map_type = BPF_MAP_TYPE_STACK_TRACE;
    } else if (A->getName() == "maps/extern") {
      if (!fe_.table_storage().Find(global_path, table_it)) {
        error(Decl->getLocStart(), "reference to undefined table");
        return false;
      }
      table = table_it->second.dup();
      table.is_extern = true;
    } else if (A->getName() == "maps/export") {
      if (table.name.substr(0, 2) == "__")
        table.name = table.name.substr(2);
      Path local_path({fe_.id(), table.name});
      Path global_path({table.name});
      if (!fe_.table_storage().Find(local_path, table_it)) {
        error(Decl->getLocStart(), "reference to undefined table");
        return false;
      }
      fe_.table_storage().Insert(global_path, table_it->second.dup());
      return true;
    }

    if (!table.is_extern) {
      if (map_type == BPF_MAP_TYPE_UNSPEC) {
        error(Decl->getLocStart(), "unsupported map type: %0") << A->getName();
        return false;
      }

      table.type = map_type;
      table.fd = bpf_create_map(map_type, table.key_size, table.leaf_size, table.max_entries, table.flags);
    }
    if (table.fd < 0) {
      error(Decl->getLocStart(), "could not open bpf map: %0\nis %1 map type enabled in your kernel?") <<
          strerror(errno) << A->getName();
      return false;
    }

    fe_.table_storage().VisitMapType(table, C, key_type, leaf_type);
    fe_.table_storage().Insert(local_path, move(table));
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

BTypeConsumer::BTypeConsumer(ASTContext &C, BFrontendAction &fe) : visitor_(C, fe) {}

bool BTypeConsumer::HandleTopLevelDecl(DeclGroupRef Group) {
  for (auto D : Group)
    visitor_.TraverseDecl(D);
  return true;
}

ProbeConsumer::ProbeConsumer(ASTContext &C, Rewriter &rewriter)
    : visitor_(C, rewriter) {}

bool ProbeConsumer::HandleTopLevelDecl(DeclGroupRef Group) {
  for (auto D : Group) {
    if (FunctionDecl *F = dyn_cast<FunctionDecl>(D)) {
      if (F->isExternallyVisible() && F->hasBody()) {
        for (auto arg : F->parameters()) {
          if (arg != F->getParamDecl(0) && !arg->getType()->isFundamentalType())
            visitor_.set_ptreg(arg);
        }
        visitor_.TraverseDecl(D);
      }
    }
  }
  return true;
}

BFrontendAction::BFrontendAction(llvm::raw_ostream &os, unsigned flags, TableStorage &ts,
                                 const std::string &id, FuncSource& func_src)
    : os_(os), flags_(flags), ts_(ts), id_(id), rewriter_(new Rewriter), func_src_(func_src) {}

void BFrontendAction::EndSourceFileAction() {
  if (flags_ & DEBUG_PREPROCESSOR)
    rewriter_->getEditBuffer(rewriter_->getSourceMgr().getMainFileID()).write(llvm::errs());

  for (auto func : func_range_) {
    auto f = func.first;
    string bd = rewriter_->getRewrittenText(func_range_[f]);
    func_src_.set_src_rewritten(f, bd);
  }
  rewriter_->getEditBuffer(rewriter_->getSourceMgr().getMainFileID()).write(os_);
  os_.flush();
}

unique_ptr<ASTConsumer> BFrontendAction::CreateASTConsumer(CompilerInstance &Compiler, llvm::StringRef InFile) {
  rewriter_->setSourceMgr(Compiler.getSourceManager(), Compiler.getLangOpts());
  vector<unique_ptr<ASTConsumer>> consumers;
  consumers.push_back(unique_ptr<ASTConsumer>(new ProbeConsumer(Compiler.getASTContext(), *rewriter_)));
  consumers.push_back(unique_ptr<ASTConsumer>(new BTypeConsumer(Compiler.getASTContext(), *this)));
  return unique_ptr<ASTConsumer>(new MultiplexConsumer(std::move(consumers)));
}

}
