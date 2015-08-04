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

#pragma once

#include <fstream> // NOLINT
#include "node.h"
#include "lexer.h"
#include "scope.h"

namespace ebpf {
namespace cc {

using std::pair;
using std::string;
using std::vector;

class Parser {
 public:
  explicit Parser(const string& infile)
      : root_node_(NULL), scopes_(new Scopes), in_(infile), lexer(&in_), parser(lexer, *this) {
    // parser.set_debug_level(1);
  }
  ~Parser() { delete root_node_; }
  int parse() {
    return parser.parse();
  }

  VariableDeclStmtNode * variable_add(vector<int> *types, VariableDeclStmtNode *decl);
  VariableDeclStmtNode * variable_add(vector<int> *types, VariableDeclStmtNode *decl, ExprNode *init_expr);
  StructVariableDeclStmtNode * variable_add(StructVariableDeclStmtNode *decl, ExprNodeList *args, bool is_kv);
  StmtNode * state_add(Scopes::StateScope *scope, IdentExprNode *id1, BlockStmtNode *body);
  StmtNode * state_add(Scopes::StateScope *scope, IdentExprNode *id1, IdentExprNode *id2, BlockStmtNode *body);
  StmtNode * func_add(std::vector<int> *types, Scopes::StateScope *scope,
                      IdentExprNode *id, FormalList *formals, BlockStmtNode *body);
  StmtNode * table_add(IdentExprNode *type, IdentExprNodeList *templates, IdentExprNode *id, string *size);
  StmtNode * struct_add(IdentExprNode *type, FormalList *formals);
  StmtNode * result_add(int token, IdentExprNode *id, FormalList *formals, BlockStmtNode *body);
  bool variable_exists(VariableDeclStmtNode *decl) const;
  bool table_exists(TableDeclStmtNode *decl, bool search_local = true);
  void add_pragma(const std::string& pr, const std::string& v) { pragmas_[pr] = v; }
  void set_loc(Node *n, const BisonParser::location_type &loc) const;
  std::string pragma(const std::string &name) const;

  Node *root_node_;
  Scopes::Ptr scopes_;
  std::map<std::string, std::string> pragmas_;
 private:
  std::ifstream in_;
  Lexer lexer;
  BisonParser parser;
};

}  // namespace cc
}  // namespace ebpf
