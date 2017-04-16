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

enum class field_kind_t {
    common,
    data_loc,
    regular,
    invalid
};

static inline field_kind_t _get_field_kind(string const& line,
                                           string& field_type,
                                           string& field_name) {
  auto field_pos = line.find("field:");
  if (field_pos == string::npos)
    return field_kind_t::invalid;

  auto semi_pos = line.find(';', field_pos);
  if (semi_pos == string::npos)
    return field_kind_t::invalid;

  auto size_pos = line.find("size:", semi_pos);
  if (size_pos == string::npos)
    return field_kind_t::invalid;

  auto field = line.substr(field_pos + 6/*"field:"*/,
                           semi_pos - field_pos - 6);
  auto pos = field.find_last_of("\t ");
  if (pos == string::npos)
    return field_kind_t::invalid;

  field_type = field.substr(0, pos);
  field_name = field.substr(pos + 1);
  if (field_type.find("__data_loc") != string::npos)
    return field_kind_t::data_loc;
  if (field_name.find("common_") == 0)
    return field_kind_t::common;

  return field_kind_t::regular;
}

string TracepointTypeVisitor::GenerateTracepointStruct(
    SourceLocation loc, string const& category, string const& event) {
  string format_file = "/sys/kernel/debug/tracing/events/" +
    category + "/" + event + "/format";
  ifstream input(format_file.c_str());
  if (!input)
    return "";

  string tp_struct = "struct tracepoint__" + category + "__" + event + " {\n";
  tp_struct += "\tu64 __do_not_use__;\n";
  for (string line; getline(input, line); ) {
    string field_type, field_name;
    switch (_get_field_kind(line, field_type, field_name)) {
    case field_kind_t::invalid:
    case field_kind_t::common:
        continue;
    case field_kind_t::data_loc:
        tp_struct += "\tint data_loc_" + field_name + ";\n";
        break;
    case field_kind_t::regular:
        tp_struct += "\t" + field_type + " " + field_name + ";\n";
        break;
    }
  }

  tp_struct += "};\n";
  return tp_struct;
}

static inline bool _is_tracepoint_struct_type(string const& type_name,
                                              string& tp_category,
                                              string& tp_event) {
  // We are looking to roughly match the regex:
  //    (?:struct|class)\s+tracepoint__(\S+)__(\S+)
  // Not using std::regex because older versions of GCC don't support it yet.
  // E.g., the libstdc++ that ships with Ubuntu 14.04.
  
  auto first_space_pos = type_name.find_first_of("\t ");
  if (first_space_pos == string::npos)
    return false;
  auto first_tok = type_name.substr(0, first_space_pos);
  if (first_tok != "struct" && first_tok != "class")
    return false;

  auto non_space_pos = type_name.find_first_not_of("\t ", first_space_pos);
  auto second_space_pos = type_name.find_first_of("\t ", non_space_pos);
  auto second_tok = type_name.substr(non_space_pos,
                                     second_space_pos - non_space_pos);
  if (second_tok.find("tracepoint__") != 0)
    return false;

  auto tp_event_pos = second_tok.rfind("__");
  if (tp_event_pos == string::npos)
    return false;
  tp_event = second_tok.substr(tp_event_pos + 2);

  auto tp_category_pos = second_tok.find("__");
  if (tp_category_pos == tp_event_pos)
    return false;
  tp_category = second_tok.substr(tp_category_pos + 2,
                                  tp_event_pos - tp_category_pos - 2);
  return true;
}


bool TracepointTypeVisitor::VisitFunctionDecl(FunctionDecl *D) {
  if (D->isExternallyVisible() && D->hasBody()) {
    // If this function has a tracepoint structure as an argument,
    // add that structure declaration based on the structure name.
    for (auto it = D->param_begin(); it != D->param_end(); ++it) {
      auto arg = *it;
      auto type = arg->getType();
      if (type->isPointerType() &&
          type->getPointeeType()->isStructureOrClassType()) {
        auto type_name = QualType::getAsString(type.split());
        string tp_cat, tp_evt;
        if (_is_tracepoint_struct_type(type_name, tp_cat, tp_evt)) {
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
