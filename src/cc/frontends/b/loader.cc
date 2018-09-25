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

#include "parser.h"
#include "type_check.h"
#include "codegen_llvm.h"
#include "loader.h"

using std::string;
using std::unique_ptr;
using std::vector;

namespace ebpf {

BLoader::BLoader(unsigned flags) : flags_(flags) {
  (void)flags_;
}

BLoader::~BLoader() {
}

int BLoader::parse(llvm::Module *mod, const string &filename, const string &proto_filename,
                   TableStorage &ts, const string &id, const std::string &maps_ns) {
  int rc;

  proto_parser_ = make_unique<ebpf::cc::Parser>(proto_filename);
  rc = proto_parser_->parse();
  if (rc) {
    fprintf(stderr, "In file: %s\n", filename.c_str());
    return rc;
  }

  parser_ = make_unique<ebpf::cc::Parser>(filename);
  rc = parser_->parse();
  if (rc) {
    fprintf(stderr, "In file: %s\n", filename.c_str());
    return rc;
  }

  //ebpf::cc::Printer printer(stderr);
  //printer.visit(parser_->root_node_);

  ebpf::cc::TypeCheck type_check(parser_->scopes_.get(), proto_parser_->scopes_.get());
  auto ret = type_check.visit(parser_->root_node_);
  if (ret.code() != 0 || ret.msg().size()) {
    fprintf(stderr, "Type error @line=%d: %s\n", ret.code(), ret.msg().c_str());
    return -1;
  }

  codegen_ = ebpf::make_unique<ebpf::cc::CodegenLLVM>(mod, parser_->scopes_.get(), proto_parser_->scopes_.get());
  ret = codegen_->visit(parser_->root_node_, ts, id, maps_ns);
  if (ret.code() != 0 || ret.msg().size()) {
    fprintf(stderr, "Codegen error @line=%d: %s\n", ret.code(), ret.msg().c_str());
    return ret.code();
  }

  return 0;
}

}  // namespace ebpf
