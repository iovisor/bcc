
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Rewrite/Core/Rewriter.h>

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

struct BPFTable {
  int fd;
  size_t key_size;
  size_t leaf_size;
  size_t max_entries;
};

// Type visitor and rewriter for B programs.
// It will look for B-specific features and rewrite them into a valid
// C program. As part of the processing, open the necessary BPF tables
// and store the open handles in a map of table-to-fd's.
class BTypeVisitor : public clang::RecursiveASTVisitor<BTypeVisitor> {
 public:
  explicit BTypeVisitor(clang::ASTContext &C, clang::Rewriter &rewriter,
                        std::map<std::string, BPFTable> &tables);
  bool VisitFunctionDecl(clang::FunctionDecl *D);
  bool VisitCallExpr(clang::CallExpr *Call);
  bool VisitVarDecl(clang::VarDecl *Decl);
  bool VisitArraySubscriptExpr(clang::ArraySubscriptExpr *E);
  bool VisitDeclRefExpr(clang::DeclRefExpr *E);

 private:
  clang::ASTContext &C;
  clang::Rewriter &rewriter_;  /// modifications to the source go into this class
  llvm::raw_ostream &out_;  /// for debugging
  std::map<std::string, BPFTable> &tables_;  /// store the open FDs
};

// A helper class to the frontend action, walks the decls
class BTypeConsumer : public clang::ASTConsumer {
 public:
  explicit BTypeConsumer(clang::ASTContext &C, clang::Rewriter &rewriter,
                         std::map<std::string, BPFTable> &tables);
  bool HandleTopLevelDecl(clang::DeclGroupRef D) override;
 private:
  BTypeVisitor visitor_;
};

// Create a B program in 2 phases (everything else is normal C frontend):
// 1. Catch the map declarations and open the fd's
// 2. Capture the IR
class BFrontendAction : public clang::ASTFrontendAction {
 public:
  // Initialize with the output stream where the new source file contents
  // should be written.
  explicit BFrontendAction(llvm::raw_ostream &os);

  // Called by clang when the AST has been completed, here the output stream
  // will be flushed.
  void EndSourceFileAction() override;

  std::unique_ptr<clang::ASTConsumer>
      CreateASTConsumer(clang::CompilerInstance &Compiler, llvm::StringRef InFile) override;

  // take ownership of the table-to-fd mapping data structure
  std::unique_ptr<std::map<std::string, BPFTable>> take_tables() { return move(tables_); }
 private:
  std::unique_ptr<clang::Rewriter> rewriter_;
  llvm::raw_ostream &os_;
  std::unique_ptr<std::map<std::string, BPFTable>> tables_;
};

}  // namespace visitor
