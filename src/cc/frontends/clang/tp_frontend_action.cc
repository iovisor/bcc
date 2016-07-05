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
#include <linux/bpf.h>
#include <linux/version.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <fstream>
#include <regex>

#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/RecordLayout.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/MultiplexConsumer.h>
#include <clang/Rewrite/Core/Rewriter.h>

#include "tp_frontend_action.h"

namespace ebpf {

using std::map;
using std::set;
using std::string;
using std::to_string;
using std::unique_ptr;
using std::vector;
using std::regex;
using std::smatch;
using std::regex_search;
using std::ifstream;
using namespace clang;

TracepointTypeVisitor::TracepointTypeVisitor(ASTContext &C, Rewriter &rewriter)
    : C(C), diag_(C.getDiagnostics()), rewriter_(rewriter), out_(llvm::errs()) {
}

string TracepointTypeVisitor::GenerateTracepointStruct(
    SourceLocation loc, string const& category, string const& event) {
  static regex field_regex("field:([^;]*);.*size:\\d+;");
  string format_file = "/sys/kernel/debug/tracing/events/" +
    category + "/" + event + "/format";
  ifstream input(format_file.c_str());
  if (!input)
    return "";

  string tp_struct = "struct tracepoint__" + category + "__" + event + " {\n";
  tp_struct += "\tu64 __do_not_use__;\n";
  for (string line; getline(input, line); ) {
    smatch field_match;
    if (!regex_search(line, field_match, field_regex))
      continue;

    string field = field_match[1];
    auto pos = field.find_last_of("\t ");
    if (pos == string::npos)
      continue;

    string field_type = field.substr(0, pos);
    string field_name = field.substr(pos + 1);
    if (field_type.find("__data_loc") != string::npos)
      continue;
    if (field_name.find("common_") == 0)
      continue;

    tp_struct += "\t" + field_type + " " + field_name + ";\n";
  }

  tp_struct += "};\n";
  return tp_struct;
}

bool TracepointTypeVisitor::VisitFunctionDecl(FunctionDecl *D) {
  static regex type_regex("(?:struct|class)\\s+tracepoint__(\\S+)__(\\S+)");
  if (D->isExternallyVisible() && D->hasBody()) {
    // If this function has a tracepoint structure as an argument,
    // add that structure declaration based on the structure name.
    for (auto arg : D->params()) {
      auto type = arg->getType();
      if (type->isPointerType() &&
          type->getPointeeType()->isStructureOrClassType()) {
        auto type_name = QualType::getAsString(type.split());
        smatch type_match;
        if (regex_search(type_name, type_match, type_regex)) {
          string tp_cat = type_match[1], tp_evt = type_match[2]; 
          string tp_struct = GenerateTracepointStruct(
              D->getLocStart(), tp_cat, tp_evt);

          // Get the actual function declaration point (the macro instantiation
          // point if using the TRACEPOINT_PROBE macro instead of the macro
          // declaration point in bpf_helpers.h).
          auto insert_loc = D->getLocStart();
          insert_loc = rewriter_.getSourceMgr().getFileLoc(insert_loc);
          rewriter_.InsertText(insert_loc, tp_struct);
        }
      }
    }
  }
  return true;
}

TracepointTypeConsumer::TracepointTypeConsumer(ASTContext &C, Rewriter &rewriter)
    : visitor_(C, rewriter) {
}

bool TracepointTypeConsumer::HandleTopLevelDecl(DeclGroupRef Group) {
  for (auto D : Group)
    visitor_.TraverseDecl(D);
  return true;
}

TracepointFrontendAction::TracepointFrontendAction(llvm::raw_ostream &os)
    : os_(os), rewriter_(new Rewriter) {
}

void TracepointFrontendAction::EndSourceFileAction() {
  rewriter_->getEditBuffer(rewriter_->getSourceMgr().getMainFileID()).write(os_);
  os_.flush();
}

unique_ptr<ASTConsumer> TracepointFrontendAction::CreateASTConsumer(
        CompilerInstance &Compiler, llvm::StringRef InFile) {
  rewriter_->setSourceMgr(Compiler.getSourceManager(), Compiler.getLangOpts());
  return unique_ptr<ASTConsumer>(new TracepointTypeConsumer(
              Compiler.getASTContext(), *rewriter_));
}

}
