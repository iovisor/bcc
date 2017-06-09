/*
 * Copyright (c) 2016 Sasha Goldshtein
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

// Visit functions that have a tracepoint argument structure in their signature
// and automatically generate the structure on-the-fly.
class TracepointTypeVisitor :
  public clang::RecursiveASTVisitor<TracepointTypeVisitor> {
 public:
  explicit TracepointTypeVisitor(clang::ASTContext &C,
                                 clang::Rewriter &rewriter);
  bool VisitFunctionDecl(clang::FunctionDecl *D);

 private:
  std::string GenerateTracepointStruct(clang::SourceLocation loc,
          std::string const& category, std::string const& event);

  clang::ASTContext &C;
  clang::DiagnosticsEngine &diag_;
  clang::Rewriter &rewriter_;
  llvm::raw_ostream &out_;
};

class TracepointTypeConsumer : public clang::ASTConsumer {
 public:
  explicit TracepointTypeConsumer(clang::ASTContext &C,
                                  clang::Rewriter &rewriter);
  bool HandleTopLevelDecl(clang::DeclGroupRef Group) override;
 private:
  TracepointTypeVisitor visitor_;
};

class TracepointFrontendAction : public clang::ASTFrontendAction {
 public:
  TracepointFrontendAction(llvm::raw_ostream &os);

  void EndSourceFileAction() override;

  std::unique_ptr<clang::ASTConsumer>
      CreateASTConsumer(clang::CompilerInstance &Compiler, llvm::StringRef InFile) override;

 private:
  llvm::raw_ostream &os_;
  std::unique_ptr<clang::Rewriter> rewriter_;
};

}  // namespace visitor
