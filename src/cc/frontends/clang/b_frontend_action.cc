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
#include <stdlib.h>

#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/RecordLayout.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/MultiplexConsumer.h>
#include <clang/Rewrite/Core/Rewriter.h>
#include <clang/Lex/Lexer.h>

#include "frontend_action_common.h"
#include "b_frontend_action.h"
#include "bpf_module.h"
#include "common.h"
#include "loader.h"
#include "table_storage.h"
#include "arch_helper.h"
#include "bcc_libbpf_inc.h"

#include "libbpf.h"
#include "bcc_syms.h"

namespace ebpf {

constexpr int MAX_CALLING_CONV_REGS = 6;
const char *calling_conv_regs_x86[] = {
  "di", "si", "dx", "cx", "r8", "r9"
};
const char *calling_conv_syscall_regs_x86[] = {
  "di", "si", "dx", "r10", "r8", "r9"
};
const char *calling_conv_regs_ppc[] = {"gpr[3]", "gpr[4]", "gpr[5]",
                                       "gpr[6]", "gpr[7]", "gpr[8]"};

const char *calling_conv_regs_s390x[] = {"gprs[2]", "gprs[3]", "gprs[4]",
					 "gprs[5]", "gprs[6]" };

const char *calling_conv_regs_arm64[] = {"regs[0]", "regs[1]", "regs[2]",
                                       "regs[3]", "regs[4]", "regs[5]"};

const char *calling_conv_regs_mips[] = {"regs[4]", "regs[5]", "regs[6]",
                                       "regs[7]", "regs[8]", "regs[9]"};

const char *calling_conv_regs_riscv64[] = {"a0", "a1", "a2",
                                       "a3", "a4", "a5"};

const char *calling_conv_regs_loongarch[] = {"regs[4]", "regs[5]", "regs[6]",
					     "regs[7]", "regs[8]", "regs[9]"};


void *get_call_conv_cb(bcc_arch_t arch, bool for_syscall)
{
  const char **ret;

  switch(arch) {
    case BCC_ARCH_PPC:
    case BCC_ARCH_PPC_LE:
      ret = calling_conv_regs_ppc;
      break;
    case BCC_ARCH_S390X:
      ret = calling_conv_regs_s390x;
      break;
    case BCC_ARCH_ARM64:
      ret = calling_conv_regs_arm64;
      break;
    case BCC_ARCH_MIPS:
      ret = calling_conv_regs_mips;
      break;
    case BCC_ARCH_RISCV64:
      ret = calling_conv_regs_riscv64;
      break;
    case BCC_ARCH_LOONGARCH:
      ret = calling_conv_regs_loongarch;
      break;
    default:
      if (for_syscall)
        ret = calling_conv_syscall_regs_x86;
      else
        ret = calling_conv_regs_x86;
  }

  return (void *)ret;
}

const char **get_call_conv(bool for_syscall = false) {
  const char **ret;

  ret = (const char **)run_arch_callback(get_call_conv_cb, for_syscall);
  return ret;
}

/* Use resolver only once per translation */
static void *kresolver = NULL;
static void *get_symbol_resolver(void) {
  if (!kresolver)
    kresolver = bcc_symcache_new(-1, nullptr);
  return kresolver;
}

static std::string check_bpf_probe_read_kernel(void) {
  bool is_probe_read_kernel;
  void *resolver = get_symbol_resolver();
  uint64_t addr = 0;
  is_probe_read_kernel = bcc_symcache_resolve_name(resolver, nullptr,
                          "bpf_probe_read_kernel", &addr) >= 0 ? true: false;

  /* If bpf_probe_read is not found (ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE) is
   * not set in newer kernel, then bcc would anyway fail */
  if (is_probe_read_kernel)
    return "bpf_probe_read_kernel";
  else
    return "bpf_probe_read";
}

static std::string check_bpf_probe_read_user(llvm::StringRef probe,
        bool& overlap_addr) {
  if (probe.str() == "bpf_probe_read_user" ||
      probe.str() == "bpf_probe_read_user_str") {
    // Check for probe_user symbols in backported kernel before fallback
    void *resolver = get_symbol_resolver();
    uint64_t addr = 0;
    bool found = bcc_symcache_resolve_name(resolver, nullptr,
                  "bpf_probe_read_user", &addr) >= 0 ? true: false;
    if (found)
      return probe.str();

    /* For arch with overlapping address space, dont use bpf_probe_read for
     * user read. Just error out */
#if defined(__s390x__)
    overlap_addr = true;
    return "";
#endif

    if (probe.str() == "bpf_probe_read_user")
      return "bpf_probe_read";
    else
      return "bpf_probe_read_str";
  }
  return "";
}

using std::map;
using std::move;
using std::set;
using std::tuple;
using std::make_tuple;
using std::string;
using std::to_string;
using std::unique_ptr;
using std::vector;
using namespace clang;

class ProbeChecker : public RecursiveASTVisitor<ProbeChecker> {
 public:
  explicit ProbeChecker(Expr *arg, const set<tuple<Decl *, int>> &ptregs,
                        bool track_helpers, bool is_assign)
      : needs_probe_(false), is_transitive_(false), ptregs_(ptregs),
        track_helpers_(track_helpers), nb_derefs_(0), is_assign_(is_assign) {
    if (arg) {
      TraverseStmt(arg);
      if (arg->getType()->isPointerType())
        is_transitive_ = needs_probe_;
    }
  }
  explicit ProbeChecker(Expr *arg, const set<tuple<Decl *, int>> &ptregs,
                        bool is_transitive)
      : ProbeChecker(arg, ptregs, is_transitive, false) {}
  bool VisitCallExpr(CallExpr *E) {
    needs_probe_ = false;

    if (is_assign_) {
      // We're looking for a function that returns an external pointer,
      // regardless of the number of dereferences.
      for(auto p : ptregs_) {
        if (std::get<0>(p) == E->getDirectCallee()) {
          needs_probe_ = true;
          // ptregs_ stores the number of dereferences needed to get the external
          // pointer, while nb_derefs_ stores the number of dereferences
          // encountered.  So, any dereference encountered is one less
          // dereference needed to get the external pointer.
          nb_derefs_ -= std::get<1>(p);
          return false;
        }
      }
    } else {
      tuple<Decl *, int> pt = make_tuple(E->getDirectCallee(), nb_derefs_);
      if (ptregs_.find(pt) != ptregs_.end())
        needs_probe_ = true;
    }

    if (!track_helpers_)
      return false;
    if (VarDecl *V = dyn_cast<VarDecl>(E->getCalleeDecl()))
      needs_probe_ = V->getName() == "bpf_get_current_task";
    return false;
  }
  bool VisitMemberExpr(MemberExpr *M) {
    tuple<Decl *, int> pt = make_tuple(M->getMemberDecl(), nb_derefs_);
    if (ptregs_.find(pt) != ptregs_.end()) {
      needs_probe_ = true;
      return false;
    }
    if (M->isArrow()) {
      /* In A->b, if A is an external pointer, then A->b should be considered
       * one too.  However, if we're taking the address of A->b
       * (nb_derefs_ < 0), we should take it into account for the number of
       * indirections; &A->b is a pointer to A with an offset. */
      if (nb_derefs_ >= 0) {
        ProbeChecker checker = ProbeChecker(M->getBase(), ptregs_,
                                            track_helpers_, is_assign_);
        if (checker.needs_probe() && checker.get_nb_derefs() == 0) {
          needs_probe_ = true;
          return false;
        }
      }
      nb_derefs_++;
    }
    return true;
  }
  bool VisitUnaryOperator(UnaryOperator *E) {
    if (E->getOpcode() == UO_Deref) {
      /* In *A, if A is an external pointer, then *A should be considered one
       * too. */
      ProbeChecker checker = ProbeChecker(E->getSubExpr(), ptregs_,
                                          track_helpers_, is_assign_);
      if (checker.needs_probe() && checker.get_nb_derefs() == 0) {
        needs_probe_ = true;
        return false;
      }
      nb_derefs_++;
    } else if (E->getOpcode() == UO_AddrOf) {
      nb_derefs_--;
    }
    return true;
  }
  bool VisitDeclRefExpr(DeclRefExpr *E) {
    if (is_assign_) {
      // We're looking for an external pointer, regardless of the number of
      // dereferences.
      for(auto p : ptregs_) {
        if (std::get<0>(p) == E->getDecl()) {
          needs_probe_ = true;
          // ptregs_ stores the number of dereferences needed to get the external
          // pointer, while nb_derefs_ stores the number of dereferences
          // encountered.  So, any dereference encountered is one less
          // dereference needed to get the external pointer.
          nb_derefs_ -= std::get<1>(p);
          return false;
        }
      }
    } else {
      tuple<Decl *, int> pt = make_tuple(E->getDecl(), nb_derefs_);
      if (ptregs_.find(pt) != ptregs_.end())
        needs_probe_ = true;
    }
    return true;
  }
  bool needs_probe() const { return needs_probe_; }
  bool is_transitive() const { return is_transitive_; }
  int get_nb_derefs() const { return nb_derefs_; }
 private:
  bool needs_probe_;
  bool is_transitive_;
  const set<tuple<Decl *, int>> &ptregs_;
  bool track_helpers_;
  // Nb of dereferences we go through before finding the external pointer.
  // A negative number counts the number of addrof.
  int nb_derefs_;
  bool is_assign_;
};

// Visit a piece of the AST and mark it as needing probe reads
class ProbeSetter : public RecursiveASTVisitor<ProbeSetter> {
 public:
  explicit ProbeSetter(set<tuple<Decl *, int>> *ptregs, int nb_derefs)
      : ptregs_(ptregs), nb_derefs_(nb_derefs) {}
  bool VisitDeclRefExpr(DeclRefExpr *E) {
    tuple<Decl *, int> pt = make_tuple(E->getDecl(), nb_derefs_);
    ptregs_->insert(pt);
    return true;
  }
  explicit ProbeSetter(set<tuple<Decl *, int>> *ptregs)
      : ProbeSetter(ptregs, 0) {}
  bool VisitUnaryOperator(UnaryOperator *E) {
    if (E->getOpcode() == UO_Deref)
      nb_derefs_++;
    return true;
  }
  bool VisitMemberExpr(MemberExpr *M) {
    tuple<Decl *, int> pt = make_tuple(M->getMemberDecl(), nb_derefs_);
    ptregs_->insert(pt);
    return false;
  }
 private:
  set<tuple<Decl *, int>> *ptregs_;
  // Nb of dereferences we go through before getting to the actual variable.
  int nb_derefs_;
};

MapVisitor::MapVisitor(set<Decl *> &m) : m_(m) {}

bool MapVisitor::VisitCallExpr(CallExpr *Call) {
  if (MemberExpr *Memb = dyn_cast<MemberExpr>(Call->getCallee()->IgnoreImplicit())) {
    StringRef memb_name = Memb->getMemberDecl()->getName();
    if (DeclRefExpr *Ref = dyn_cast<DeclRefExpr>(Memb->getBase())) {
      if (SectionAttr *A = Ref->getDecl()->getAttr<SectionAttr>()) {
        if (!A->getName().startswith("maps"))
          return true;

        if (memb_name == "update" || memb_name == "insert") {
          ProbeChecker checker = ProbeChecker(Call->getArg(1), ptregs_, true,
                                              true);
          if (checker.needs_probe())
            m_.insert(Ref->getDecl());
        }
      }
    }
  }
  return true;
}

ProbeVisitor::ProbeVisitor(ASTContext &C, Rewriter &rewriter,
                           set<Decl *> &m, bool track_helpers) :
  C(C), rewriter_(rewriter), m_(m), ctx_(nullptr), track_helpers_(track_helpers),
  addrof_stmt_(nullptr), is_addrof_(false) {
  const char **calling_conv_regs = get_call_conv();
  cannot_fall_back_safely = (calling_conv_regs == calling_conv_regs_s390x || calling_conv_regs == calling_conv_regs_riscv64);
}

bool ProbeVisitor::assignsExtPtr(Expr *E, int *nbDerefs) {
  if (IsContextMemberExpr(E)) {
    *nbDerefs = 0;
    return true;
  }

  /* If the expression contains a call to another function, we need to visit
  * that function first to know if a rewrite is necessary (i.e., if the
  * function returns an external pointer). */
  if (!TraverseStmt(E))
    return false;

  ProbeChecker checker = ProbeChecker(E, ptregs_, track_helpers_,
                                      true);
  if (checker.is_transitive()) {
    // The negative of the number of dereferences is the number of addrof.  In
    // an assignment, if we went through n addrof before getting the external
    // pointer, then we'll need n dereferences on the left-hand side variable
    // to get to the external pointer.
    *nbDerefs = -checker.get_nb_derefs();
    return true;
  }

  if (E->IgnoreParenCasts()->getStmtClass() == Stmt::CallExprClass) {
    CallExpr *Call = dyn_cast<CallExpr>(E->IgnoreParenCasts());
    if (MemberExpr *Memb = dyn_cast<MemberExpr>(Call->getCallee()->IgnoreImplicit())) {
      StringRef memb_name = Memb->getMemberDecl()->getName();
      if (DeclRefExpr *Ref = dyn_cast<DeclRefExpr>(Memb->getBase())) {
        if (SectionAttr *A = Ref->getDecl()->getAttr<SectionAttr>()) {
          if (!A->getName().startswith("maps"))
            return false;

          if (memb_name == "lookup" || memb_name == "lookup_or_init" ||
              memb_name == "lookup_or_try_init") {
            if (m_.find(Ref->getDecl()) != m_.end()) {
              // Retrieved an ext. pointer from a map, mark LHS as ext. pointer.
              // Pointers from maps always need a single dereference to get the
              // actual value.  The value may be an external pointer but cannot
              // be a pointer to an external pointer as the verifier prohibits
              // storing known pointers (to map values, context, the stack, or
              // the packet) in maps.
              *nbDerefs = 1;
              return true;
            }
          }
        }
      }
    }
  }
  return false;
}
bool ProbeVisitor::VisitVarDecl(VarDecl *D) {
  if (Expr *E = D->getInit()) {
    int nbDerefs;
    if (assignsExtPtr(E, &nbDerefs)) {
      // The negative of the number of addrof is the number of dereferences.
      tuple<Decl *, int> pt = make_tuple(D, nbDerefs);
      set_ptreg(pt);
    }
  }
  return true;
}

bool ProbeVisitor::TraverseStmt(Stmt *S) {
  if (whitelist_.find(S) != whitelist_.end())
    return true;
  auto ret = RecursiveASTVisitor<ProbeVisitor>::TraverseStmt(S);
  if (addrof_stmt_ == S) {
    addrof_stmt_ = nullptr;
    is_addrof_ = false;
  }
  return ret;
}

bool ProbeVisitor::VisitCallExpr(CallExpr *Call) {
  // Skip bpf_probe_read for the third argument if it is an AddrOf.
  if (VarDecl *V = dyn_cast<VarDecl>(Call->getCalleeDecl())) {
    if (V->getName() == "bpf_probe_read" && Call->getNumArgs() >= 3) {
      const Expr *E = Call->getArg(2)->IgnoreParenCasts();
      whitelist_.insert(E);
      return true;
    }
  }

  if (FunctionDecl *F = dyn_cast<FunctionDecl>(Call->getCalleeDecl())) {
    if (F->hasBody()) {
      unsigned i = 0;
      for (auto arg : Call->arguments()) {
        ProbeChecker checker = ProbeChecker(arg, ptregs_, track_helpers_,
                                            true);
        if (checker.needs_probe()) {
          tuple<Decl *, int> pt = make_tuple(F->getParamDecl(i),
                                             -checker.get_nb_derefs());
          ptregs_.insert(pt);
        }
        ++i;
      }
      if (fn_visited_.find(F) == fn_visited_.end()) {
        fn_visited_.insert(F);
        /* Maintains a stack of the number of dereferences for the external
         * pointers returned by each function in the call stack or -1 if the
         * function didn't return an external pointer. */
        ptregs_returned_.push_back(-1);
        TraverseDecl(F);
        int nb_derefs = ptregs_returned_.back();
        ptregs_returned_.pop_back();
        if (nb_derefs != -1) {
          tuple<Decl *, int> pt = make_tuple(F, nb_derefs);
          ptregs_.insert(pt);
        }
      }
    }
  }
  return true;
}
bool ProbeVisitor::VisitReturnStmt(ReturnStmt *R) {
  /* If this function wasn't called by another, there's no need to check the
   * return statement for external pointers. */
  if (ptregs_returned_.size() == 0)
    return true;

  /* Reverse order of traversals.  This is needed if, in the return statement,
   * we're calling a function that's returning an external pointer: we need to
   * know what the function is returning to decide what this function is
   * returning. */
  if (!TraverseStmt(R->getRetValue()))
    return false;

  ProbeChecker checker = ProbeChecker(R->getRetValue(), ptregs_,
                                      track_helpers_, true);
  if (checker.needs_probe()) {
    int curr_nb_derefs = ptregs_returned_.back();
    int nb_derefs = -checker.get_nb_derefs();
    /* If the function returns external pointers with different levels of
     * indirection, we handle the case with the highest level of indirection
     * and leave it to the user to manually handle other cases. */
    if (nb_derefs > curr_nb_derefs) {
      ptregs_returned_.pop_back();
      ptregs_returned_.push_back(nb_derefs);
    }
  }
  return true;
}
bool ProbeVisitor::VisitBinaryOperator(BinaryOperator *E) {
  if (!E->isAssignmentOp())
    return true;

  // copy probe attribute from RHS to LHS if present
  int nbDerefs;
  if (assignsExtPtr(E->getRHS(), &nbDerefs)) {
    ProbeSetter setter(&ptregs_, nbDerefs);
    setter.TraverseStmt(E->getLHS());
  }
  return true;
}
bool ProbeVisitor::VisitUnaryOperator(UnaryOperator *E) {
  if (E->getOpcode() == UO_AddrOf) {
    addrof_stmt_ = E;
    is_addrof_ = true;
  }
  if (E->getOpcode() != UO_Deref)
    return true;
  if (memb_visited_.find(E) != memb_visited_.end())
    return true;
  Expr *sub = E->getSubExpr();
  if (!ProbeChecker(sub, ptregs_, track_helpers_).needs_probe())
    return true;
  memb_visited_.insert(E);
  string pre, post;
  pre = "({ typeof(" + E->getType().getAsString() + ") _val; __builtin_memset(&_val, 0, sizeof(_val));";
  if (cannot_fall_back_safely)
    pre += " bpf_probe_read_kernel(&_val, sizeof(_val), (u64)";
  else
    pre += " bpf_probe_read(&_val, sizeof(_val), (u64)";
  post = "); _val; })";
  rewriter_.ReplaceText(expansionLoc(E->getOperatorLoc()), 1, pre);
  rewriter_.InsertTextAfterToken(expansionLoc(GET_ENDLOC(sub)), post);
  return true;
}
bool ProbeVisitor::VisitMemberExpr(MemberExpr *E) {
  if (memb_visited_.find(E) != memb_visited_.end()) return true;

  Expr *base;
  SourceLocation rhs_start, member;
  bool found = false;
  for (MemberExpr *M = E; M; M = dyn_cast<MemberExpr>(M->getBase())) {
    memb_visited_.insert(M);
    rhs_start = GET_ENDLOC(M);
    base = M->getBase();
    member = M->getMemberLoc();
    if (M->isArrow()) {
      found = true;
      break;
    }
  }
  if (!found)
    return true;
  if (member.isInvalid()) {
    error(GET_ENDLOC(base), "internal error: MemberLoc is invalid while preparing probe rewrite");
    return false;
  }

  if (!rewriter_.isRewritable(GET_BEGINLOC(E)))
    return true;

  // parent expr has addrof, skip the rewrite, set is_addrof_ to flase so
  // it won't affect next level of indirect address
  if (is_addrof_) {
    is_addrof_ = false;
    return true;
  }

  /* If the base of the dereference is a call to another function, we need to
   * visit that function first to know if a rewrite is necessary (i.e., if the
   * function returns an external pointer). */
  if (base->IgnoreParenCasts()->getStmtClass() == Stmt::CallExprClass) {
    CallExpr *Call = dyn_cast<CallExpr>(base->IgnoreParenCasts());
    if (!TraverseStmt(Call))
      return false;
  }

  // Checks to see if the expression references something that needs to be run
  // through bpf_probe_read.
  if (!ProbeChecker(base, ptregs_, track_helpers_).needs_probe())
    return true;

  // If the base is an array, we will skip rewriting. See issue #2352.
  if (E->getType()->isArrayType())
    return true;

  string rhs = rewriter_.getRewrittenText(expansionRange(SourceRange(rhs_start, GET_ENDLOC(E))));
  string base_type = base->getType()->getPointeeType().getAsString();
  string pre, post;
  pre = "({ typeof(" + E->getType().getAsString() + ") _val; __builtin_memset(&_val, 0, sizeof(_val));";
  if (cannot_fall_back_safely)
    pre += " bpf_probe_read_kernel(&_val, sizeof(_val), (u64)&";
  else
    pre += " bpf_probe_read(&_val, sizeof(_val), (u64)&";
  post = rhs + "); _val; })";
  rewriter_.InsertText(expansionLoc(GET_BEGINLOC(E)), pre);
  rewriter_.ReplaceText(expansionRange(SourceRange(member, GET_ENDLOC(E))), post);
  return true;
}
bool ProbeVisitor::VisitArraySubscriptExpr(ArraySubscriptExpr *E) {
  if (memb_visited_.find(E) != memb_visited_.end()) return true;
  if (!ProbeChecker(E, ptregs_, track_helpers_).needs_probe())
    return true;

  // Parent expr has addrof, skip the rewrite.
  if (is_addrof_)
    return true;

  // If the base is an array, we will skip rewriting. See issue #2352.
  if (E->getType()->isArrayType())
    return true;

  if (!rewriter_.isRewritable(GET_BEGINLOC(E)))
    return true;

  Expr *base = E->getBase();
  Expr *idx = E->getIdx();
  memb_visited_.insert(E);

  if (!rewriter_.isRewritable(GET_BEGINLOC(base)))
    return true;
  if (!rewriter_.isRewritable(GET_BEGINLOC(idx)))
    return true;


  string pre, lbracket, rbracket;
  LangOptions opts;
  SourceLocation lbracket_start, lbracket_end;
  SourceRange lbracket_range;

  /* For cases like daddr->s6_addr[4], clang encodes the end location of "base"
   * as "]". This makes it hard to rewrite the expression like
   * "daddr->s6_addr  [ 4 ]" since we do not know the end location
   * of "addr->s6_addr". Let us abort the operation if this is the case.
   */
  lbracket_start = Lexer::getLocForEndOfToken(GET_ENDLOC(base), 1,
                                              rewriter_.getSourceMgr(),
                                              opts).getLocWithOffset(1);
  lbracket_end = GET_BEGINLOC(idx).getLocWithOffset(-1);
  lbracket_range = expansionRange(SourceRange(lbracket_start, lbracket_end));
  if (rewriter_.getRewrittenText(lbracket_range).size() == 0)
    return true;

  pre = "({ typeof(" + E->getType().getAsString() + ") _val; __builtin_memset(&_val, 0, sizeof(_val));";
  if (cannot_fall_back_safely)
    pre += " bpf_probe_read_kernel(&_val, sizeof(_val), (u64)((";
  else
    pre += " bpf_probe_read(&_val, sizeof(_val), (u64)((";
  if (isMemberDereference(base)) {
    pre += "&";
    // If the base of the array subscript is a member dereference, we'll rewrite
    // both at the same time.
    addrof_stmt_ = base;
    is_addrof_ = true;
  }
  rewriter_.InsertText(expansionLoc(GET_BEGINLOC(base)), pre);

  /* Replace left bracket and any space around it.  Since Clang doesn't provide
   * a method to retrieve the left bracket, replace everything from the end of
   * the base to the start of the index. */
  lbracket = ") + (";
  rewriter_.ReplaceText(lbracket_range, lbracket);

  rbracket = "))); _val; })";
  rewriter_.ReplaceText(expansionLoc(E->getRBracketLoc()), 1, rbracket);

  return true;
}

bool ProbeVisitor::isMemberDereference(Expr *E) {
  if (E->IgnoreParenCasts()->getStmtClass() != Stmt::MemberExprClass)
    return false;
  for (MemberExpr *M = dyn_cast<MemberExpr>(E->IgnoreParenCasts()); M;
       M = dyn_cast<MemberExpr>(M->getBase()->IgnoreParenCasts())) {
    if (M->isArrow())
      return true;
  }
  return false;
}
bool ProbeVisitor::IsContextMemberExpr(Expr *E) {
  if (!E->getType()->isPointerType())
    return false;

  Expr *base;
  SourceLocation member;
  bool found = false;
  MemberExpr *M;
  Expr *Ex = E->IgnoreParenCasts();
  while (Ex->getStmtClass() == Stmt::ArraySubscriptExprClass
         || Ex->getStmtClass() == Stmt::MemberExprClass) {
    if (Ex->getStmtClass() == Stmt::ArraySubscriptExprClass) {
      Ex = dyn_cast<ArraySubscriptExpr>(Ex)->getBase()->IgnoreParenCasts();
    } else if (Ex->getStmtClass() == Stmt::MemberExprClass) {
      M = dyn_cast<MemberExpr>(Ex);
      base = M->getBase()->IgnoreParenCasts();
      member = M->getMemberLoc();
      if (M->isArrow()) {
        found = true;
        break;
      }
      Ex = base;
    }
  }
  if (!found) {
    return false;
  }
  if (member.isInvalid()) {
    return false;
  }

  if (DeclRefExpr *base_expr = dyn_cast<DeclRefExpr>(base)) {
    if (base_expr->getDecl() == ctx_) {
      return true;
    }
  }
  return false;
}

SourceRange
ProbeVisitor::expansionRange(SourceRange range) {
#if LLVM_MAJOR_VERSION >= 7
  return rewriter_.getSourceMgr().getExpansionRange(range).getAsRange();
#else
  return rewriter_.getSourceMgr().getExpansionRange(range);
#endif
}

SourceLocation
ProbeVisitor::expansionLoc(SourceLocation loc) {
  return rewriter_.getSourceMgr().getExpansionLoc(loc);
}

template <unsigned N>
DiagnosticBuilder ProbeVisitor::error(SourceLocation loc, const char (&fmt)[N]) {
  unsigned int diag_id = C.getDiagnostics().getCustomDiagID(DiagnosticsEngine::Error, fmt);
  return C.getDiagnostics().Report(loc, diag_id);
}

BTypeVisitor::BTypeVisitor(ASTContext &C, BFrontendAction &fe)
    : C(C), diag_(C.getDiagnostics()), fe_(fe), rewriter_(fe.rewriter()), out_(llvm::errs()) {
  const char **calling_conv_regs = get_call_conv();
  cannot_fall_back_safely = (calling_conv_regs == calling_conv_regs_s390x || calling_conv_regs == calling_conv_regs_riscv64);
}

void BTypeVisitor::genParamDirectAssign(FunctionDecl *D, string& preamble,
                                        const char **calling_conv_regs) {
  for (size_t idx = 0; idx < fn_args_.size(); idx++) {
    ParmVarDecl *arg = fn_args_[idx];

    if (idx >= 1) {
      // Move the args into a preamble section where the same params are
      // declared and initialized from pt_regs.
      // Todo: this init should be done only when the program requests it.
      string text = rewriter_.getRewrittenText(expansionRange(arg->getSourceRange()));
      arg->addAttr(UnavailableAttr::CreateImplicit(C, "ptregs"));
      size_t d = idx - 1;
      const char *reg = calling_conv_regs[d];
      preamble += " " + text + " = " + fn_args_[0]->getName().str() + "->" +
                  string(reg) + ";";
    }
  }
}

void BTypeVisitor::genParamIndirectAssign(FunctionDecl *D, string& preamble,
                                          const char **calling_conv_regs) {
  string new_ctx;

  for (size_t idx = 0; idx < fn_args_.size(); idx++) {
    ParmVarDecl *arg = fn_args_[idx];

    if (idx == 0) {
      new_ctx = "__" + arg->getName().str();
      preamble += " struct pt_regs * " + new_ctx + " = " +
                  arg->getName().str() + "->" +
                  string(calling_conv_regs[0]) + ";";
    } else {
      // Move the args into a preamble section where the same params are
      // declared and initialized from pt_regs.
      // Todo: this init should be done only when the program requests it.
      string text = rewriter_.getRewrittenText(expansionRange(arg->getSourceRange()));
      size_t d = idx - 1;
      const char *reg = calling_conv_regs[d];
      preamble += "\n " + text + ";";
      if (cannot_fall_back_safely)
        preamble += " bpf_probe_read_kernel";
      else
        preamble += " bpf_probe_read";
      preamble += "(&" + arg->getName().str() + ", sizeof(" +
                  arg->getName().str() + "), &" + new_ctx + "->" +
                  string(reg) + ");";
    }
  }
}

void BTypeVisitor::rewriteFuncParam(FunctionDecl *D) {
  string preamble = "{\n";
  if (D->param_size() > 1) {
    bool is_syscall = false;
    if (strncmp(D->getName().str().c_str(), "syscall__", 9) == 0 ||
        strncmp(D->getName().str().c_str(), "kprobe____x64_sys_", 18) == 0)
      is_syscall = true;
    const char **calling_conv_regs = get_call_conv(is_syscall);

    // If function prefix is "syscall__" or "kprobe____x64_sys_",
    // the function will attach to a kprobe syscall function.
    // Guard parameter assiggnment with CONFIG_ARCH_HAS_SYSCALL_WRAPPER.
    // For __x64_sys_* syscalls, this is always true, but we guard
    // it in case of "syscall__" for other architectures.
    if (is_syscall) {
      preamble += "#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)\n";
      genParamIndirectAssign(D, preamble, calling_conv_regs);
      preamble += "\n#else\n";
      genParamDirectAssign(D, preamble, calling_conv_regs);
      preamble += "\n#endif\n";
    } else {
      genParamDirectAssign(D, preamble, calling_conv_regs);
    }
    rewriter_.ReplaceText(
        expansionRange(SourceRange(GET_ENDLOC(D->getParamDecl(0)),
                    GET_ENDLOC(D->getParamDecl(D->getNumParams() - 1)))),
        fn_args_[0]->getName());
  }
  // for each trace argument, convert the variable from ptregs to something on stack
  if (CompoundStmt *S = dyn_cast<CompoundStmt>(D->getBody()))
    rewriter_.ReplaceText(S->getLBracLoc(), 1, preamble);
}

bool BTypeVisitor::VisitFunctionDecl(FunctionDecl *D) {
  // put each non-static non-inline function decl in its own section, to be
  // extracted by the MemoryManager
  auto real_start_loc = rewriter_.getSourceMgr().getFileLoc(GET_BEGINLOC(D));
  if (fe_.is_rewritable_ext_func(D)) {
    current_fn_ = string(D->getName());
    string bd = rewriter_.getRewrittenText(expansionRange(D->getSourceRange()));
    auto func_info = fe_.prog_func_info_.add_func(current_fn_);
    if (!func_info) {
      // We should only reach add_func above once per function seen, but the
      // BPF_PROG-helper using macros in export/helpers.h (KFUNC_PROBE ..
      // LSM_PROBE) break this logic. TODO: adjust export/helpers.h to not
      // do so and bail out here, or find a better place to do add_func
      func_info = fe_.prog_func_info_.get_func(current_fn_);
      //error(GET_BEGINLOC(D), "redefinition of existing function");
      //return false;
    }
    func_info->src_ = bd;
    fe_.func_range_[current_fn_] = expansionRange(D->getSourceRange());
    if (!D->getAttr<SectionAttr>()) {
      string attr = string("__attribute__((section(\"") + BPF_FN_PREFIX +
                    D->getName().str() + "\")))\n";
      rewriter_.InsertText(real_start_loc, attr);
    }
    if (D->param_size() > MAX_CALLING_CONV_REGS + 1) {
      error(GET_BEGINLOC(D->getParamDecl(MAX_CALLING_CONV_REGS + 1)),
            "too many arguments, bcc only supports in-register parameters");
      return false;
    }

    fn_args_.clear();
    for (auto arg_it = D->param_begin(); arg_it != D->param_end(); arg_it++) {
      auto *arg = *arg_it;
      if (arg->getName() == "") {
        error(GET_ENDLOC(arg), "arguments to BPF program definition must be named");
        return false;
      }
      fn_args_.push_back(arg);
    }
    rewriteFuncParam(D);
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

        string args = rewriter_.getRewrittenText(expansionRange(SourceRange(GET_BEGINLOC(Call->getArg(0)),
                                                   GET_ENDLOC(Call->getArg(Call->getNumArgs() - 1)))));

        // find the table fd, which was opened at declaration time
        TableStorage::iterator desc;
        Path local_path({fe_.id(), string(Ref->getDecl()->getName())});
        Path global_path({string(Ref->getDecl()->getName())});
        if (!fe_.table_storage().Find(local_path, desc)) {
          if (!fe_.table_storage().Find(global_path, desc)) {
            error(GET_ENDLOC(Ref), "bpf_table %0 failed to open") << Ref->getDecl()->getName();
            return false;
          }
        }
        string fd = to_string(desc->second.fd >= 0 ? desc->second.fd : desc->second.fake_fd);
        string prefix, suffix;
        string txt;
        auto rewrite_start = GET_BEGINLOC(Call);
        auto rewrite_end = GET_ENDLOC(Call);
        if (memb_name == "lookup_or_init" || memb_name == "lookup_or_try_init") {
          string name = string(Ref->getDecl()->getName());
          string arg0 = rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));
          string arg1 = rewriter_.getRewrittenText(expansionRange(Call->getArg(1)->getSourceRange()));
          string lookup = "bpf_map_lookup_elem_(bpf_pseudo_fd(1, " + fd + ")";
          string update = "bpf_map_update_elem_(bpf_pseudo_fd(1, " + fd + ")";
          txt  = "({typeof(" + name + ".leaf) *leaf = " + lookup + ", " + arg0 + "); ";
          txt += "if (!leaf) {";
          txt += " " + update + ", " + arg0 + ", " + arg1 + ", BPF_NOEXIST);";
          txt += " leaf = " + lookup + ", " + arg0 + ");";
          if (memb_name == "lookup_or_init") {
            txt += " if (!leaf) return 0;";
          }
          txt += "}";
          txt += "leaf;})";
        } else if (memb_name == "increment" || memb_name == "atomic_increment") {
          string name = string(Ref->getDecl()->getName());
          string arg0 = rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));

          string increment_value = "1";
          if (Call->getNumArgs() == 2) {
            increment_value = rewriter_.getRewrittenText(expansionRange(Call->getArg(1)->getSourceRange()));

          }

          string lookup = "bpf_map_lookup_elem_(bpf_pseudo_fd(1, " + fd + ")";
          string update = "bpf_map_update_elem_(bpf_pseudo_fd(1, " + fd + ")";
          txt  = "({ typeof(" + name + ".key) _key = " + arg0 + "; ";
          txt += "typeof(" + name + ".leaf) *_leaf = " + lookup + ", &_key); ";
          txt += "if (_leaf) ";

          if (memb_name == "atomic_increment") {
            txt += "lock_xadd(_leaf, " + increment_value + ");";
          } else {
            txt += "(*_leaf) += " + increment_value + ";";
          }
          if (desc->second.type == BPF_MAP_TYPE_HASH) {
            txt += "else { typeof(" + name + ".leaf) _zleaf; __builtin_memset(&_zleaf, 0, sizeof(_zleaf)); ";
            txt += "_zleaf += " + increment_value + ";";
            txt += update + ", &_key, &_zleaf, BPF_NOEXIST); } ";
          }
          txt += "})";
        } else if (memb_name == "perf_submit") {
          string name = string(Ref->getDecl()->getName());
          string arg0 = rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));
          string args_other = rewriter_.getRewrittenText(expansionRange(SourceRange(GET_BEGINLOC(Call->getArg(1)),
                                                           GET_ENDLOC(Call->getArg(2)))));
          txt = "bpf_perf_event_output(" + arg0 + ", (void *)bpf_pseudo_fd(1, " + fd + ")";
          txt += ", CUR_CPU_IDENTIFIER, " + args_other + ")";

          // e.g.
          // struct data_t { u32 pid; }; data_t data;
          // events.perf_submit(ctx, &data, sizeof(data));
          // ...
          //                       &data   ->     data    ->  typeof(data)        ->   data_t
          auto type_arg1 = Call->getArg(1)->IgnoreCasts()->getType().getTypePtr()->getPointeeType().getTypePtrOrNull();
          if (type_arg1 && type_arg1->isStructureType()) {
            auto event_type = type_arg1->getAsTagDecl();
            const auto *r = dyn_cast<RecordDecl>(event_type);
            std::vector<std::string> perf_event;

            for (auto it = r->field_begin(); it != r->field_end(); ++it) {
              // After LLVM commit aee49255074f
              // (https://github.com/llvm/llvm-project/commit/aee49255074fd4ef38d97e6e70cbfbf2f9fd0fa7)
              // array type change from `comm#char [16]` to `comm#char[16]`
              perf_event.push_back(it->getNameAsString() + "#" + it->getType().getAsString()); //"pid#u32"
            }
            fe_.perf_events_[name] = perf_event;
          }
        } else if (memb_name == "perf_submit_skb") {
          string skb = rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));
          string skb_len = rewriter_.getRewrittenText(expansionRange(Call->getArg(1)->getSourceRange()));
          string meta = rewriter_.getRewrittenText(expansionRange(Call->getArg(2)->getSourceRange()));
          string meta_len = rewriter_.getRewrittenText(expansionRange(Call->getArg(3)->getSourceRange()));
          txt = "bpf_perf_event_output(" +
            skb + ", " +
            "(void *)bpf_pseudo_fd(1, " + fd + "), " +
            "((__u64)" + skb_len + " << 32) | BPF_F_CURRENT_CPU, " +
            meta + ", " +
            meta_len + ");";
        } else if (memb_name == "get_stackid") {
          if (desc->second.type == BPF_MAP_TYPE_STACK_TRACE) {
            string arg0 =
                rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));
            txt = "bcc_get_stackid(";
            txt += "bpf_pseudo_fd(1, " + fd + "), " + arg0;
            rewrite_end = GET_ENDLOC(Call->getArg(0));
            } else {
              error(GET_BEGINLOC(Call), "get_stackid only available on stacktrace maps");
              return false;
            }
        } else if (memb_name == "sock_map_update" || memb_name == "sock_hash_update") {
          string ctx = rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));
          string keyp = rewriter_.getRewrittenText(expansionRange(Call->getArg(1)->getSourceRange()));
          string flag = rewriter_.getRewrittenText(expansionRange(Call->getArg(2)->getSourceRange()));
          txt = "bpf_" + string(memb_name) + "(" + ctx + ", " +
            "(void *)bpf_pseudo_fd(1, " + fd + "), " + keyp + ", " + flag + ");";
        } else if (memb_name == "ringbuf_output") {
          string name = string(Ref->getDecl()->getName());
          string args = rewriter_.getRewrittenText(expansionRange(SourceRange(GET_BEGINLOC(Call->getArg(0)),
                                                           GET_ENDLOC(Call->getArg(2)))));
          txt = "bpf_ringbuf_output((void *)bpf_pseudo_fd(1, " + fd + ")";
          txt += ", " + args + ")";

          // e.g.
          // struct data_t { u32 pid; }; data_t data;
          // events.ringbuf_output(&data, sizeof(data), 0);
          // ...
          //                       &data   ->     data    ->  typeof(data)        ->   data_t
          auto type_arg0 = Call->getArg(0)->IgnoreCasts()->getType().getTypePtr()->getPointeeType().getTypePtr();
          if (type_arg0->isStructureType()) {
            auto event_type = type_arg0->getAsTagDecl();
            const auto *r = dyn_cast<RecordDecl>(event_type);
            std::vector<std::string> perf_event;

            for (auto it = r->field_begin(); it != r->field_end(); ++it) {
              perf_event.push_back(it->getNameAsString() + "#" + it->getType().getAsString()); //"pid#u32"
            }
            fe_.perf_events_[name] = perf_event;
          }
        } else if (memb_name == "ringbuf_reserve") {
          string name = string(Ref->getDecl()->getName());
          string arg0 = rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));
          txt = "bpf_ringbuf_reserve((void *)bpf_pseudo_fd(1, " + fd + ")";
          txt += ", " + arg0 + ", 0)"; // Flags in reserve are meaningless
        } else if (memb_name == "ringbuf_discard") {
          string name = string(Ref->getDecl()->getName());
          string args = rewriter_.getRewrittenText(expansionRange(SourceRange(GET_BEGINLOC(Call->getArg(0)),
                                                           GET_ENDLOC(Call->getArg(1)))));
          txt = "bpf_ringbuf_discard(" + args + ")";
        } else if (memb_name == "ringbuf_submit") {
          string name = string(Ref->getDecl()->getName());
          string args = rewriter_.getRewrittenText(expansionRange(SourceRange(GET_BEGINLOC(Call->getArg(0)),
                                                           GET_ENDLOC(Call->getArg(1)))));
          txt = "bpf_ringbuf_submit(" + args + ")";

          // e.g.
          // struct data_t { u32 pid; };
          // data_t *data = events.ringbuf_reserve(sizeof(data_t));
          // events.ringbuf_submit(data, 0);
          // ...
          //                       &data   ->     data    ->  typeof(data)        ->   data_t
          auto type_arg0 = Call->getArg(0)->IgnoreCasts()->getType().getTypePtr()->getPointeeType().getTypePtr();
          if (type_arg0->isStructureType()) {
            auto event_type = type_arg0->getAsTagDecl();
            const auto *r = dyn_cast<RecordDecl>(event_type);
            std::vector<std::string> perf_event;

            for (auto it = r->field_begin(); it != r->field_end(); ++it) {
              perf_event.push_back(it->getNameAsString() + "#" + it->getType().getAsString()); //"pid#u32"
            }
            fe_.perf_events_[name] = perf_event;
          }
        } else if (memb_name == "msg_redirect_hash" || memb_name == "sk_redirect_hash") {
          string arg0 = rewriter_.getRewrittenText(expansionRange(Call->getArg(0)->getSourceRange()));
          string args_other = rewriter_.getRewrittenText(expansionRange(SourceRange(GET_BEGINLOC(Call->getArg(1)),
                                                           GET_ENDLOC(Call->getArg(2)))));

          txt = "bpf_" + string(memb_name) + "(" + arg0 + ", (void *)bpf_pseudo_fd(1, " + fd + "), ";
          txt += args_other + ")";
        } else {
          if (memb_name == "lookup") {
            prefix = "bpf_map_lookup_elem";
            suffix = ")";
          } else if (memb_name == "update") {
            prefix = "bpf_map_update_elem";
            suffix = ", BPF_ANY)";
          } else if (memb_name == "insert") {
            if (desc->second.type == BPF_MAP_TYPE_ARRAY) {
              warning(GET_BEGINLOC(Call), "all element of an array already exist; insert() will have no effect");
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
          } else if (memb_name == "perf_counter_value") {
            prefix = "bpf_perf_event_read_value";
            suffix = ")";
          } else if (memb_name == "check_current_task") {
            prefix = "bpf_current_task_under_cgroup";
            suffix = ")";
          } else if (memb_name == "redirect_map") {
            prefix = "bpf_redirect_map";
            suffix = ")";
          } else if (memb_name == "sk_storage_get") {
            prefix = "bpf_sk_storage_get";
            suffix = ")";
          } else if (memb_name == "sk_storage_delete") {
            prefix = "bpf_sk_storage_delete";
            suffix = ")";
          } else if (memb_name == "inode_storage_get") {
            prefix = "bpf_inode_storage_get";
            suffix = ")";
          } else if (memb_name == "inode_storage_delete") {
            prefix = "bpf_inode_storage_delete";
            suffix = ")";
          } else if (memb_name == "task_storage_get") {
            prefix = "bpf_task_storage_get";
            suffix = ")";
          } else if (memb_name == "task_storage_delete") {
            prefix = "bpf_task_storage_delete";
            suffix = ")";
          } else if (memb_name == "get_local_storage") {
            prefix = "bpf_get_local_storage";
            suffix = ")";
          } else if (memb_name == "push") {
            prefix = "bpf_map_push_elem";
            suffix = ")";
          } else if (memb_name == "pop") {
            prefix = "bpf_map_pop_elem";
            suffix = ")";
          } else if (memb_name == "peek") {
            prefix = "bpf_map_peek_elem";
            suffix = ")";
           } else {
            error(GET_BEGINLOC(Call), "invalid bpf_table operation %0") << memb_name;
            return false;
          }
          prefix += "((void *)bpf_pseudo_fd(1, " + fd + "), ";

          txt = prefix + args + suffix;
        }
        if (!rewriter_.isRewritable(rewrite_start) || !rewriter_.isRewritable(rewrite_end)) {
          error(GET_BEGINLOC(Call), "cannot use map function inside a macro");
          return false;
        }
        rewriter_.ReplaceText(expansionRange(SourceRange(rewrite_start, rewrite_end)), txt);
        return true;
      }
    }
  } else if (Call->getCalleeDecl()) {
    NamedDecl *Decl = dyn_cast<NamedDecl>(Call->getCalleeDecl());
    if (!Decl) return true;

    string text;

    // Bail out when bpf_probe_read_user is unavailable for overlapping address
    // space arch.
    bool overlap_addr = false;
    std::string probe = check_bpf_probe_read_user(Decl->getName(),
                          overlap_addr);
    if (overlap_addr) {
      error(GET_BEGINLOC(Call), "bpf_probe_read_user not found. Use latest kernel");
      return false;
    }

    if (AsmLabelAttr *A = Decl->getAttr<AsmLabelAttr>()) {
      // Functions with the tag asm("llvm.bpf.extra") are implemented in the
      // rewriter rather than as a macro since they may also include nested
      // rewrites, and clang::Rewriter does not support rewrites in macros,
      // unless one preprocesses the entire source file.
      if (A->getLabel() == "llvm.bpf.extra") {
        if (!rewriter_.isRewritable(GET_BEGINLOC(Call))) {
          error(GET_BEGINLOC(Call), "cannot use builtin inside a macro");
          return false;
        }

        vector<string> args;

        for (auto arg : Call->arguments())
          args.push_back(rewriter_.getRewrittenText(expansionRange(arg->getSourceRange())));

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
          checkFormatSpecifiers(args[0], GET_BEGINLOC(Call->getArg(0)));
          //  #define bpf_trace_printk(fmt, args...)
          //    ({ char _fmt[] = fmt; bpf_trace_printk_(_fmt, sizeof(_fmt), args...); })
          text = "({ char _fmt[] = " + args[0] + "; bpf_trace_printk_(_fmt, sizeof(_fmt)";
          if (args.size() <= 1) {
            text += "); })";
            rewriter_.ReplaceText(expansionRange(Call->getSourceRange()), text);
          } else {
            rewriter_.ReplaceText(expansionRange(SourceRange(GET_BEGINLOC(Call), GET_ENDLOC(Call->getArg(0)))), text);
            rewriter_.InsertTextAfter(GET_ENDLOC(Call), "); }");
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

          bool overlap_addr = false;
          text += check_bpf_probe_read_user(StringRef("bpf_probe_read_user"),
                  overlap_addr);
          if (overlap_addr) {
            error(GET_BEGINLOC(Call), "bpf_probe_read_user not found. Use latest kernel");
            return false;
          }

          text += "(" + args[2] + ", " + args[3] + ", (void *)__addr);";
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
        auto start_loc = rewriter_.getSourceMgr().getFileLoc(GET_BEGINLOC(Decl));
        if (rewriter_.getSourceMgr().getFileID(start_loc)
            == rewriter_.getSourceMgr().getMainFileID()) {
          error(GET_BEGINLOC(Call), "cannot call non-static helper function");
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
            if (!rewriter_.isRewritable(GET_BEGINLOC(E))) {
              error(GET_BEGINLOC(E), "cannot use \"packet\" header type inside a macro");
              return false;
            }

            auto EndLoc = GET_ENDLOC(E);
            if (EndLoc.isMacroID()) {
              error(EndLoc, "cannot have macro at the end of expresssion, "
                            "workaround: put perentheses around macro \"(MARCO)\"");
              return false;
            }

            uint64_t ofs = C.getFieldOffset(F);
            uint64_t sz = F->isBitField() ? F->getBitWidthValue(C) : C.getTypeSize(F->getType());
            string base = rewriter_.getRewrittenText(expansionRange(Base->getSourceRange()));
            string text = "bpf_dins_pkt(" + fn_args_[0]->getName().str() + ", (u64)" + base + "+" + to_string(ofs >> 3)
                + ", " + to_string(ofs & 0x7) + ", " + to_string(sz) + ",";
            rewriter_.ReplaceText(expansionRange(SourceRange(GET_BEGINLOC(E), E->getOperatorLoc())), text);
            rewriter_.InsertTextAfterToken(EndLoc, ")");
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
          if (!rewriter_.isRewritable(GET_BEGINLOC(E))) {
            error(GET_BEGINLOC(E), "cannot use \"packet\" header type inside a macro");
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
#if LLVM_MAJOR_VERSION >= 7
  return rewriter_.getSourceMgr().getExpansionRange(range).getAsRange();
#else
  return rewriter_.getSourceMgr().getExpansionRange(range);
#endif
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

int64_t BTypeVisitor::getFieldValue(VarDecl *Decl, FieldDecl *FDecl, int64_t OrigFValue) {
  unsigned idx = FDecl->getFieldIndex();

  if (auto I = dyn_cast_or_null<InitListExpr>(Decl->getInit())) {
#if LLVM_MAJOR_VERSION >= 8
    Expr::EvalResult res;
    if (I->getInit(idx)->EvaluateAsInt(res, C)) {
      return res.Val.getInt().getExtValue();
    }
#else
    llvm::APSInt res;
    if (I->getInit(idx)->EvaluateAsInt(res, C)) {
      return res.getExtValue();
    }
#endif
  }

  return OrigFValue;
}

// Open table FDs when bpf tables (as denoted by section("maps*") attribute)
// are declared.
bool BTypeVisitor::VisitVarDecl(VarDecl *Decl) {
  const RecordType *R = Decl->getType()->getAs<RecordType>();
  if (SectionAttr *A = Decl->getAttr<SectionAttr>()) {
    if (!A->getName().startswith("maps"))
      return true;
    if (!R) {
      error(GET_ENDLOC(Decl), "invalid type for bpf_table, expect struct");
      return false;
    }
    const RecordDecl *RD = R->getDecl()->getDefinition();

    TableDesc table;
    TableStorage::iterator table_it;
    table.name = string(Decl->getName());
    Path local_path({fe_.id(), table.name});
    Path maps_ns_path({"ns", fe_.maps_ns(), table.name});
    Path global_path({table.name});
    QualType key_type, leaf_type;

    unsigned i = 0;
    for (auto F : RD->fields()) {
      if (F->getType().getTypePtr()->isIncompleteType()) {
        error(GET_BEGINLOC(F), "unknown type");
        return false;
      }

      size_t sz = C.getTypeSize(F->getType()) >> 3;
      if (F->getName() == "key") {
        if (sz == 0) {
          error(GET_BEGINLOC(F), "invalid zero-sized leaf");
          return false;
        }
        table.key_size = sz;
        key_type = F->getType();
      } else if (F->getName() == "leaf") {
        if (sz == 0) {
          error(GET_BEGINLOC(F), "invalid zero-sized leaf");
          return false;
        }
        table.leaf_size = sz;
        leaf_type = F->getType();
      } else if (F->getName() == "max_entries") {
            table.max_entries = getFieldValue(Decl, F, table.max_entries);
      } else if (F->getName() == "flags") {
            table.flags = getFieldValue(Decl, F, table.flags);
      }
      ++i;
    }

    std::string section_attr = string(A->getName()), pinned;
    size_t pinned_path_pos = section_attr.find(":");
    // 0 is not a valid map ID, -1 is to create and pin it to file
    int pinned_id = 0;

    if (pinned_path_pos != std::string::npos) {
      pinned = section_attr.substr(pinned_path_pos + 1);
      section_attr = section_attr.substr(0, pinned_path_pos);
      int fd = bpf_obj_get(pinned.c_str());
      if (fd < 0) {
        if (bcc_make_parent_dir(pinned.c_str()) ||
            bcc_check_bpffs_path(pinned.c_str())) {
          return false;
        }

        pinned_id = -1;
      } else {
        struct bpf_map_info info = {};
        unsigned int info_len = sizeof(info);

        if (bpf_obj_get_info_by_fd(fd, &info, &info_len)) {
          error(GET_BEGINLOC(Decl), "get map info failed: %0")
                << strerror(errno);
          return false;
        }

        pinned_id = info.id;
      }

      close(fd);
    }

    // Additional map specific information
    size_t map_info_pos = section_attr.find("$");
    std::string inner_map_name;

    if (map_info_pos != std::string::npos) {
      std::string map_info = section_attr.substr(map_info_pos + 1);
      section_attr = section_attr.substr(0, map_info_pos);
      if (section_attr == "maps/array_of_maps" ||
          section_attr == "maps/hash_of_maps") {
        inner_map_name = map_info;
      }
    }

    bpf_map_type map_type = BPF_MAP_TYPE_UNSPEC;
    if (section_attr == "maps/hash") {
      map_type = BPF_MAP_TYPE_HASH;
    } else if (section_attr == "maps/array") {
      map_type = BPF_MAP_TYPE_ARRAY;
    } else if (section_attr == "maps/percpu_hash") {
      map_type = BPF_MAP_TYPE_PERCPU_HASH;
    } else if (section_attr == "maps/percpu_array") {
      map_type = BPF_MAP_TYPE_PERCPU_ARRAY;
    } else if (section_attr == "maps/lru_hash") {
      map_type = BPF_MAP_TYPE_LRU_HASH;
    } else if (section_attr == "maps/lru_percpu_hash") {
      map_type = BPF_MAP_TYPE_LRU_PERCPU_HASH;
    } else if (section_attr == "maps/lpm_trie") {
      map_type = BPF_MAP_TYPE_LPM_TRIE;
    } else if (section_attr == "maps/histogram") {
      map_type = BPF_MAP_TYPE_HASH;
      if (key_type->isSpecificBuiltinType(BuiltinType::Int))
        map_type = BPF_MAP_TYPE_ARRAY;
      if (!leaf_type->isSpecificBuiltinType(BuiltinType::ULongLong))
        error(GET_BEGINLOC(Decl), "histogram leaf type must be u64, got %0") << leaf_type;
    } else if (section_attr == "maps/prog") {
      map_type = BPF_MAP_TYPE_PROG_ARRAY;
    } else if (section_attr == "maps/perf_output") {
      map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
      int numcpu = get_possible_cpus().size();
      if (numcpu <= 0)
        numcpu = 1;
      table.max_entries = numcpu;
    } else if (section_attr == "maps/ringbuf") {
      map_type = BPF_MAP_TYPE_RINGBUF;
      // values from libbpf/src/libbpf_probes.c
      table.key_size = 0;
      table.leaf_size = 0;
    } else if (section_attr == "maps/perf_array") {
      map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
    } else if (section_attr == "maps/queue") {
      table.key_size = 0;
      map_type = BPF_MAP_TYPE_QUEUE;
    } else if (section_attr == "maps/stack") {
      table.key_size = 0;
      map_type = BPF_MAP_TYPE_STACK;
    } else if (section_attr == "maps/cgroup_array") {
      map_type = BPF_MAP_TYPE_CGROUP_ARRAY;
    } else if (section_attr == "maps/stacktrace") {
      map_type = BPF_MAP_TYPE_STACK_TRACE;
    } else if (section_attr == "maps/devmap") {
      map_type = BPF_MAP_TYPE_DEVMAP;
    } else if (section_attr == "maps/cpumap") {
      map_type = BPF_MAP_TYPE_CPUMAP;
    } else if (section_attr == "maps/xskmap") {
      map_type = BPF_MAP_TYPE_XSKMAP;
    } else if (section_attr == "maps/hash_of_maps") {
      map_type = BPF_MAP_TYPE_HASH_OF_MAPS;
    } else if (section_attr == "maps/array_of_maps") {
      map_type = BPF_MAP_TYPE_ARRAY_OF_MAPS;
    } else if (section_attr == "maps/sk_storage") {
      map_type = BPF_MAP_TYPE_SK_STORAGE;
    } else if (section_attr == "maps/inode_storage") {
      map_type = BPF_MAP_TYPE_INODE_STORAGE;
    } else if (section_attr == "maps/task_storage") {
      map_type = BPF_MAP_TYPE_TASK_STORAGE;
    } else if (section_attr == "maps/sockmap") {
      map_type = BPF_MAP_TYPE_SOCKMAP;
    } else if (section_attr == "maps/sockhash") {
      map_type = BPF_MAP_TYPE_SOCKHASH;
    } else if (section_attr == "maps/cgroup_storage") {
      map_type = BPF_MAP_TYPE_CGROUP_STORAGE;
    } else if (section_attr == "maps/percpu_cgroup_storage") {
      map_type = BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE;
    } else if (section_attr == "maps/extern") {
      if (!fe_.table_storage().Find(maps_ns_path, table_it)) {
        if (!fe_.table_storage().Find(global_path, table_it)) {
          error(GET_BEGINLOC(Decl), "reference to undefined table");
          return false;
        }
      }
      table = table_it->second.dup();
      table.is_extern = true;
    } else if (section_attr == "maps/export") {
      if (table.name.substr(0, 2) == "__")
        table.name = table.name.substr(2);
      Path local_path({fe_.id(), table.name});
      Path global_path({table.name});
      if (!fe_.table_storage().Find(local_path, table_it)) {
        error(GET_BEGINLOC(Decl), "reference to undefined table");
        return false;
      }
      fe_.table_storage().Insert(global_path, table_it->second.dup());
      return true;
    } else if(section_attr == "maps/shared") {
      if (table.name.substr(0, 2) == "__")
        table.name = table.name.substr(2);
      Path local_path({fe_.id(), table.name});
      Path maps_ns_path({"ns", fe_.maps_ns(), table.name});
      if (!fe_.table_storage().Find(local_path, table_it)) {
        error(GET_BEGINLOC(Decl), "reference to undefined table");
        return false;
      }
      fe_.table_storage().Insert(maps_ns_path, table_it->second.dup());
      return true;
    }

    if (!table.is_extern) {
      if (map_type == BPF_MAP_TYPE_UNSPEC) {
        error(GET_BEGINLOC(Decl), "unsupported map type: %0") << section_attr;
        return false;
      }

      table.type = map_type;
      table.fake_fd = fe_.get_next_fake_fd();
      fe_.add_map_def(table.fake_fd, std::make_tuple((int)map_type, std::string(table.name),
                      (int)table.key_size, (int)table.leaf_size,
                      (int)table.max_entries, table.flags, pinned_id,
                      inner_map_name, pinned));
    }

    if (!table.is_extern)
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

// First traversal of AST to retrieve maps with external pointers.
BTypeConsumer::BTypeConsumer(ASTContext &C, BFrontendAction &fe,
                             Rewriter &rewriter, set<Decl *> &m)
    : fe_(fe),
      map_visitor_(m),
      btype_visitor_(C, fe),
      probe_visitor1_(C, rewriter, m, true),
      probe_visitor2_(C, rewriter, m, false) {}

void BTypeConsumer::HandleTranslationUnit(ASTContext &Context) {
  DeclContext::decl_iterator it;
  DeclContext *DC = TranslationUnitDecl::castToDeclContext(Context.getTranslationUnitDecl());

  /**
   * In a first traversal, ProbeVisitor tracks external pointers identified
   * through each function's arguments and replaces their dereferences with
   * calls to bpf_probe_read. It also passes all identified pointers to
   * external addresses to MapVisitor.
   */
  for (it = DC->decls_begin(); it != DC->decls_end(); it++) {
    Decl *D = *it;
    if (FunctionDecl *F = dyn_cast<FunctionDecl>(D)) {
      if (fe_.is_rewritable_ext_func(F)) {
        for (auto arg : F->parameters()) {
          if (arg == F->getParamDecl(0)) {
            /**
             * Limit tracing of pointers from context to tracing contexts.
             * We're whitelisting instead of blacklisting to avoid issues with
             * existing programs if new context types are added in the future.
             */
            string type = arg->getType().getAsString();
            if (type == "struct pt_regs *" ||
                type == "struct bpf_raw_tracepoint_args *" ||
                type.substr(0, 19) == "struct tracepoint__")
              probe_visitor1_.set_ctx(arg);
          } else if (!arg->getType()->isFundamentalType()) {
            tuple<Decl *, int> pt = make_tuple(arg, 0);
            probe_visitor1_.set_ptreg(pt);
          }
        }

        probe_visitor1_.TraverseDecl(D);
        for (auto ptreg : probe_visitor1_.get_ptregs()) {
          map_visitor_.set_ptreg(ptreg);
        }
      }
    }
  }

  /**
   * MapVisitor uses external pointers identified by the first ProbeVisitor
   * traversal to identify all maps with external pointers as values.
   * MapVisitor runs only after ProbeVisitor finished its traversal of the
   * whole translation unit to clearly separate the role of each ProbeVisitor's
   * traversal: the first tracks external pointers from function arguments,
   * whereas the second tracks external pointers from maps. Without this clear
   * separation, ProbeVisitor might attempt to replace several times the same
   * dereferences.
   */
  for (it = DC->decls_begin(); it != DC->decls_end(); it++) {
    Decl *D = *it;
    if (FunctionDecl *F = dyn_cast<FunctionDecl>(D)) {
      if (fe_.is_rewritable_ext_func(F)) {
        map_visitor_.TraverseDecl(D);
      }
    }
  }

  /**
   * In a second traversal, ProbeVisitor tracks pointers passed through the
   * maps identified by MapVisitor and replaces their dereferences with calls
   * to bpf_probe_read.
   * This last traversal runs after MapVisitor went through an entire
   * translation unit, to ensure maps with external pointers have all been
   * identified.
   */
  for (it = DC->decls_begin(); it != DC->decls_end(); it++) {
    Decl *D = *it;
    if (FunctionDecl *F = dyn_cast<FunctionDecl>(D)) {
      if (fe_.is_rewritable_ext_func(F)) {
        probe_visitor2_.TraverseDecl(D);
      }
    }

    btype_visitor_.TraverseDecl(D);
  }

}

BFrontendAction::BFrontendAction(
    llvm::raw_ostream &os, unsigned flags, TableStorage &ts,
    const std::string &id, const std::string &main_path,
    ProgFuncInfo &prog_func_info, std::string &mod_src,
    const std::string &maps_ns, fake_fd_map_def &fake_fd_map,
    std::map<std::string, std::vector<std::string>> &perf_events)
    : os_(os),
      flags_(flags),
      ts_(ts),
      id_(id),
      maps_ns_(maps_ns),
      rewriter_(new Rewriter),
      main_path_(main_path),
      prog_func_info_(prog_func_info),
      mod_src_(mod_src),
      next_fake_fd_(-1),
      fake_fd_map_(fake_fd_map),
      perf_events_(perf_events) {}

bool BFrontendAction::is_rewritable_ext_func(FunctionDecl *D) {
  StringRef file_name = rewriter_->getSourceMgr().getFilename(GET_BEGINLOC(D));
  return (D->isExternallyVisible() && D->hasBody() &&
          (file_name.empty() || file_name == main_path_));
}

void BFrontendAction::DoMiscWorkAround() {
  // In 4.16 and later, CONFIG_CC_STACKPROTECTOR is moved out of Kconfig and into
  // Makefile. It will be set depending on CONFIG_CC_STACKPROTECTOR_{AUTO|REGULAR|STRONG}.
  // CONFIG_CC_STACKPROTECTOR is still used in various places, e.g., struct task_struct,
  // to guard certain fields. The workaround here intends to define
  // CONFIG_CC_STACKPROTECTOR properly based on other configs, so it relieved any bpf
  // program (using task_struct, etc.) of patching the below code.
  std::string probefunc = check_bpf_probe_read_kernel();
  if (kresolver) {
    bcc_free_symcache(kresolver, -1);
    kresolver = NULL;
  }
  if (probefunc == "bpf_probe_read") {
    probefunc = "#define bpf_probe_read_kernel bpf_probe_read\n"
      "#define bpf_probe_read_kernel_str bpf_probe_read_str\n"
      "#define bpf_probe_read_user bpf_probe_read\n"
      "#define bpf_probe_read_user_str bpf_probe_read_str\n";
  }
  else {
    probefunc = "";
  }
  std::string prologue = "#if defined(BPF_LICENSE)\n"
    "#error BPF_LICENSE cannot be specified through cflags\n"
    "#endif\n"
    "#if !defined(CONFIG_CC_STACKPROTECTOR)\n"
    "#if defined(CONFIG_CC_STACKPROTECTOR_AUTO) \\\n"
    "    || defined(CONFIG_CC_STACKPROTECTOR_REGULAR) \\\n"
    "    || defined(CONFIG_CC_STACKPROTECTOR_STRONG)\n"
    "#define CONFIG_CC_STACKPROTECTOR\n"
    "#endif\n"
    "#endif\n";
  prologue = prologue + probefunc;
  rewriter_->getEditBuffer(rewriter_->getSourceMgr().getMainFileID()).InsertText(0,
    prologue,
    false);

  rewriter_->getEditBuffer(rewriter_->getSourceMgr().getMainFileID()).InsertTextAfter(
#if LLVM_MAJOR_VERSION >= 12
    rewriter_->getSourceMgr().getBufferOrFake(rewriter_->getSourceMgr().getMainFileID()).getBufferSize(),
#else
    rewriter_->getSourceMgr().getBuffer(rewriter_->getSourceMgr().getMainFileID())->getBufferSize(),
#endif
    "\n#include <bcc/footer.h>\n");
}

void BFrontendAction::EndSourceFileAction() {
  // Additional misc rewrites
  DoMiscWorkAround();

  if (flags_ & DEBUG_PREPROCESSOR)
    rewriter_->getEditBuffer(rewriter_->getSourceMgr().getMainFileID()).write(llvm::errs());
#if LLVM_MAJOR_VERSION >= 9
  llvm::raw_string_ostream tmp_os(mod_src_);
  rewriter_->getEditBuffer(rewriter_->getSourceMgr().getMainFileID())
      .write(tmp_os);
#else
  if (flags_ & DEBUG_SOURCE) {
    llvm::raw_string_ostream tmp_os(mod_src_);
    rewriter_->getEditBuffer(rewriter_->getSourceMgr().getMainFileID())
        .write(tmp_os);
  }
#endif

  for (auto func : func_range_) {
    auto f = func.first;
    string bd = rewriter_->getRewrittenText(func_range_[f]);
    auto fn = prog_func_info_.get_func(f);
    if (fn)
      fn->src_rewritten_ = bd;
  }
  rewriter_->getEditBuffer(rewriter_->getSourceMgr().getMainFileID()).write(os_);
  os_.flush();
}

unique_ptr<ASTConsumer> BFrontendAction::CreateASTConsumer(CompilerInstance &Compiler, llvm::StringRef InFile) {
  rewriter_->setSourceMgr(Compiler.getSourceManager(), Compiler.getLangOpts());
  vector<unique_ptr<ASTConsumer>> consumers;
  consumers.push_back(unique_ptr<ASTConsumer>(new BTypeConsumer(Compiler.getASTContext(), *this, *rewriter_, m_)));
  return unique_ptr<ASTConsumer>(new MultiplexConsumer(std::move(consumers)));
}

}
