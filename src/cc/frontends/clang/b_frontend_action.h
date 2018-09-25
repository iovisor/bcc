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

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Rewrite/Core/Rewriter.h>

#include "table_storage.h"

namespace clang {
class ASTConsumer;
class ASTContext;
class CompilerInstance;
}

namespace llvm {
class raw_ostream;
class StringRef;
}

namespace ebpf {

class BFrontendAction;
class FuncSource;

// Traces maps with external pointers as values.
class MapVisitor : public clang::RecursiveASTVisitor<MapVisitor> {
 public:
  explicit MapVisitor(std::set<clang::Decl *> &m);
  bool VisitCallExpr(clang::CallExpr *Call);
  void set_ptreg(std::tuple<clang::Decl *, int> &pt) { ptregs_.insert(pt); }
 private:
  std::set<clang::Decl *> &m_;
  std::set<std::tuple<clang::Decl *, int>> ptregs_;
};

// Type visitor and rewriter for B programs.
// It will look for B-specific features and rewrite them into a valid
// C program. As part of the processing, open the necessary BPF tables
// and store the open handles in a map of table-to-fd's.
class BTypeVisitor : public clang::RecursiveASTVisitor<BTypeVisitor> {
 public:
  explicit BTypeVisitor(clang::ASTContext &C, BFrontendAction &fe);
  bool TraverseCallExpr(clang::CallExpr *Call);
  bool VisitFunctionDecl(clang::FunctionDecl *D);
  bool VisitCallExpr(clang::CallExpr *Call);
  bool VisitVarDecl(clang::VarDecl *Decl);
  bool VisitBinaryOperator(clang::BinaryOperator *E);
  bool VisitImplicitCastExpr(clang::ImplicitCastExpr *E);

 private:
  clang::SourceRange expansionRange(clang::SourceRange range);
  bool checkFormatSpecifiers(const std::string& fmt, clang::SourceLocation loc);
  void genParamDirectAssign(clang::FunctionDecl *D, std::string& preamble,
                            const char **calling_conv_regs);
  void genParamIndirectAssign(clang::FunctionDecl *D, std::string& preamble,
                              const char **calling_conv_regs);
  void rewriteFuncParam(clang::FunctionDecl *D);
  template <unsigned N>
  clang::DiagnosticBuilder error(clang::SourceLocation loc, const char (&fmt)[N]);
  template <unsigned N>
  clang::DiagnosticBuilder warning(clang::SourceLocation loc, const char (&fmt)[N]);

  clang::ASTContext &C;
  clang::DiagnosticsEngine &diag_;
  BFrontendAction &fe_;
  clang::Rewriter &rewriter_;  /// modifications to the source go into this class
  llvm::raw_ostream &out_;  /// for debugging
  std::vector<clang::ParmVarDecl *> fn_args_;
  std::set<clang::Expr *> visited_;
  std::string current_fn_;
};

// Do a depth-first search to rewrite all pointers that need to be probed
class ProbeVisitor : public clang::RecursiveASTVisitor<ProbeVisitor> {
 public:
  explicit ProbeVisitor(clang::ASTContext &C, clang::Rewriter &rewriter,
                        std::set<clang::Decl *> &m, bool track_helpers);
  bool VisitVarDecl(clang::VarDecl *Decl);
  bool TraverseStmt(clang::Stmt *S);
  bool VisitCallExpr(clang::CallExpr *Call);
  bool VisitReturnStmt(clang::ReturnStmt *R);
  bool VisitBinaryOperator(clang::BinaryOperator *E);
  bool VisitUnaryOperator(clang::UnaryOperator *E);
  bool VisitMemberExpr(clang::MemberExpr *E);
  bool VisitArraySubscriptExpr(clang::ArraySubscriptExpr *E);
  void set_ptreg(std::tuple<clang::Decl *, int> &pt) { ptregs_.insert(pt); }
  void set_ctx(clang::Decl *D) { ctx_ = D; }
  std::set<std::tuple<clang::Decl *, int>> get_ptregs() { return ptregs_; }
 private:
  bool assignsExtPtr(clang::Expr *E, int *nbAddrOf);
  bool isMemberDereference(clang::Expr *E);
  bool IsContextMemberExpr(clang::Expr *E);
  clang::SourceRange expansionRange(clang::SourceRange range);
  clang::SourceLocation expansionLoc(clang::SourceLocation loc);
  template <unsigned N>
  clang::DiagnosticBuilder error(clang::SourceLocation loc, const char (&fmt)[N]);

  clang::ASTContext &C;
  clang::Rewriter &rewriter_;
  std::set<clang::Decl *> fn_visited_;
  std::set<clang::Expr *> memb_visited_;
  std::set<const clang::Stmt *> whitelist_;
  std::set<std::tuple<clang::Decl *, int>> ptregs_;
  std::set<clang::Decl *> &m_;
  clang::Decl *ctx_;
  bool track_helpers_;
  std::list<int> ptregs_returned_;
  const clang::Stmt *addrof_stmt_;
  bool is_addrof_;
};

// A helper class to the frontend action, walks the decls
class BTypeConsumer : public clang::ASTConsumer {
 public:
  explicit BTypeConsumer(clang::ASTContext &C, BFrontendAction &fe,
                         clang::Rewriter &rewriter, std::set<clang::Decl *> &m);
  void HandleTranslationUnit(clang::ASTContext &Context) override;
 private:
  BFrontendAction &fe_;
  MapVisitor map_visitor_;
  BTypeVisitor btype_visitor_;
  ProbeVisitor probe_visitor1_;
  ProbeVisitor probe_visitor2_;
};

// Create a B program in 2 phases (everything else is normal C frontend):
// 1. Catch the map declarations and open the fd's
// 2. Capture the IR
class BFrontendAction : public clang::ASTFrontendAction {
 public:
  // Initialize with the output stream where the new source file contents
  // should be written.
  BFrontendAction(llvm::raw_ostream &os, unsigned flags, TableStorage &ts,
                  const std::string &id, const std::string &main_path,
                  FuncSource &func_src, std::string &mod_src,
                  const std::string &maps_ns);

  // Called by clang when the AST has been completed, here the output stream
  // will be flushed.
  void EndSourceFileAction() override;

  std::unique_ptr<clang::ASTConsumer>
      CreateASTConsumer(clang::CompilerInstance &Compiler, llvm::StringRef InFile) override;

  clang::Rewriter &rewriter() const { return *rewriter_; }
  TableStorage &table_storage() const { return ts_; }
  std::string id() const { return id_; }
  std::string maps_ns() const { return maps_ns_; }
  bool is_rewritable_ext_func(clang::FunctionDecl *D);
  void DoMiscWorkAround();

 private:
  llvm::raw_ostream &os_;
  unsigned flags_;
  TableStorage &ts_;
  std::string id_;
  std::string maps_ns_;
  std::unique_ptr<clang::Rewriter> rewriter_;
  friend class BTypeVisitor;
  std::map<std::string, clang::SourceRange> func_range_;
  const std::string &main_path_;
  FuncSource &func_src_;
  std::string &mod_src_;
  std::set<clang::Decl *> m_;
};

}  // namespace visitor
