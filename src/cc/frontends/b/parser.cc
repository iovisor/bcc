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

#include <algorithm>
#include "bcc_exception.h"
#include "parser.h"
#include "type_helper.h"

namespace ebpf {
namespace cc {

using std::find;
using std::move;
using std::string;
using std::unique_ptr;

bool Parser::variable_exists(VariableDeclStmtNode *decl) const {
  if (scopes_->current_var()->lookup(decl->id_->name_, SCOPE_LOCAL) == NULL) {
    return false;
  }
  return true;
}

VariableDeclStmtNode *Parser::variable_add(vector<int> *types, VariableDeclStmtNode *decl) {

  if (variable_exists(decl)) {
    fprintf(stderr, "redeclaration of variable %s", decl->id_->name_.c_str());
    return nullptr;
  }
  decl->scope_id_ = string("v") + std::to_string(scopes_->current_var()->id_) + string("_");
  scopes_->current_var()->add(decl->id_->name_, decl);
  return decl;
}

VariableDeclStmtNode *Parser::variable_add(vector<int> *types, VariableDeclStmtNode *decl, ExprNode *init_expr) {
  AssignExprNode::Ptr assign(new AssignExprNode(decl->id_->copy(), ExprNode::Ptr(init_expr)));
  decl->init_.push_back(move(assign));

  if (variable_exists(decl)) {
    fprintf(stderr, "redeclaration of variable %s", decl->id_->name_.c_str());
    return nullptr;
  }
  decl->scope_id_ = string("v") + std::to_string(scopes_->current_var()->id_) + string("_");
  scopes_->current_var()->add(decl->id_->name_, decl);
  return decl;
}

StructVariableDeclStmtNode *Parser::variable_add(StructVariableDeclStmtNode *decl, ExprNodeList *args, bool is_kv) {
  if (is_kv) {
    // annotate the init expressions with the declared id
    for (auto arg = args->begin(); arg != args->end(); ++arg) {
      // decorate with the name of this decl
      auto n = static_cast<AssignExprNode *>(arg->get());
      auto id = static_cast<IdentExprNode *>(n->lhs_.get());
      id->prepend_dot(decl->id_->name_);
    }
  } else {
    fprintf(stderr, "must use key = value syntax\n");
    return NULL;
  }

  decl->init_ = move(*args);
  delete args;

  if (variable_exists(decl)) {
    fprintf(stderr, "ccpg: warning: redeclaration of variable '%s'\n", decl->id_->name_.c_str());
    return nullptr;
  }
  decl->scope_id_ = string("v") + std::to_string(scopes_->current_var()->id_) + string("_");
  scopes_->current_var()->add(decl->id_->name_, decl);
  return decl;
}

StmtNode *Parser::state_add(Scopes::StateScope *scope, IdentExprNode *id, BlockStmtNode *body) {
  if (scopes_->current_state()->lookup(id->full_name(), SCOPE_LOCAL)) {
    fprintf(stderr, "redeclaration of state %s\n", id->full_name().c_str());
    // redeclaration
    return NULL;
  }
  auto state = new StateDeclStmtNode(IdentExprNode::Ptr(id), BlockStmtNode::Ptr(body));
    // add a reference to the lower scope
  state->subs_[0].scope_ = scope;

  // add me to the upper scope
  scopes_->current_state()->add(state->id_->full_name(), state);
  state->scope_id_ = string("s") + std::to_string(scopes_->current_state()->id_) + string("_");

  return state;
}

StmtNode *Parser::state_add(Scopes::StateScope *scope, IdentExprNode *id1, IdentExprNode *id2, BlockStmtNode *body) {
  auto state = scopes_->current_state()->lookup(id1->full_name(), SCOPE_LOCAL);
  if (!state) {
    state = new StateDeclStmtNode(IdentExprNode::Ptr(id1), IdentExprNode::Ptr(id2), BlockStmtNode::Ptr(body));
    // add a reference to the lower scope
    state->subs_[0].scope_ = scope;

    // add me to the upper scope
    scopes_->current_state()->add(state->id_->full_name(), state);
    state->scope_id_ = string("s") + std::to_string(scopes_->current_state()->id_) + string("_");
    return state;
  } else {
    if (state->find_sub(id2->name_) != state->subs_.end()) {
      fprintf(stderr, "redeclaration of state %s, %s\n", id1->full_name().c_str(), id2->full_name().c_str());
      return NULL;
    }
    state->subs_.push_back(StateDeclStmtNode::Sub(IdentExprNode::Ptr(id2), BlockStmtNode::Ptr(body),
                                                  ParserStateStmtNode::Ptr(), scope));
    delete id1;

    return new StateDeclStmtNode(); // stub
  }
}

bool Parser::table_exists(TableDeclStmtNode *decl, bool search_local) {
  if (scopes_->top_table()->lookup(decl->id_->name_, search_local) == NULL) {
    return false;
  }
  return true;
}

StmtNode *Parser::table_add(IdentExprNode *type, IdentExprNodeList *templates,
                            IdentExprNode *id, string *size) {
  auto table = new TableDeclStmtNode(IdentExprNode::Ptr(type),
                                     move(*templates),
                                     IdentExprNode::Ptr(id), size);
  if (table_exists(table, true)) {
    fprintf(stderr, "redeclaration of table %s\n", id->name_.c_str());
    return table;
  }
  scopes_->top_table()->add(id->name_, table);
  return table;
}

StmtNode * Parser::struct_add(IdentExprNode *type, FormalList *formals) {
  auto struct_decl = new StructDeclStmtNode(IdentExprNode::Ptr(type), move(*formals));
  if (scopes_->top_struct()->lookup(type->name_, SCOPE_LOCAL) != NULL) {
    fprintf(stderr, "redeclaration of struct %s\n", type->name_.c_str());
    return struct_decl;
  }

  auto pr_it = pragmas_.find("packed");
  if (pr_it != pragmas_.end() && pr_it->second == "true")
    struct_decl->packed_ = true;

  int i = 0;
  size_t offset = 0;
  for (auto it = struct_decl->stmts_.begin(); it != struct_decl->stmts_.end(); ++it, ++i) {
    FieldType ft = bits_to_enum((*it)->bit_width_);
    offset = struct_decl->is_packed() ? offset : align_offset(offset, ft);
    (*it)->slot_ = i;
    (*it)->bit_offset_ = offset;
    offset += (*it)->bit_width_;
  }
  struct_decl->bit_width_ = struct_decl->is_packed() ? offset : align_offset(offset, UINT32_T);

  scopes_->top_struct()->add(type->name_, struct_decl);
  return struct_decl;
}

StmtNode * Parser::result_add(int token, IdentExprNode *id, FormalList *formals, BlockStmtNode *body) {
  StmtNode *stmt = NULL;
  switch (token) {
    case Tok::TMATCH:
      stmt = new MatchDeclStmtNode(IdentExprNode::Ptr(id), move(*formals), BlockStmtNode::Ptr(body));
      break;
    case Tok::TMISS:
      stmt = new MissDeclStmtNode(IdentExprNode::Ptr(id), move(*formals), BlockStmtNode::Ptr(body));
      break;
    case Tok::TFAILURE:
      stmt = new FailureDeclStmtNode(IdentExprNode::Ptr(id), move(*formals), BlockStmtNode::Ptr(body));
      break;
    default:
      {}
  }
  return stmt;
}

StmtNode * Parser::func_add(vector<int> *types, Scopes::StateScope *scope,
                            IdentExprNode *id, FormalList *formals, BlockStmtNode *body) {
  auto decl = new FuncDeclStmtNode(IdentExprNode::Ptr(id), move(*formals), BlockStmtNode::Ptr(body));
  if (scopes_->top_func()->lookup(decl->id_->name_, SCOPE_LOCAL)) {
    fprintf(stderr, "redeclaration of func %s\n", id->name_.c_str());
    return decl;
  }
  auto cur_scope = scopes_->current_var();
  scopes_->set_current(scope);
  for (auto it = formals->begin(); it != formals->end(); ++it)
    if (!variable_add(nullptr, it->get())) {
      delete decl;
      return nullptr;
    }
  scopes_->set_current(cur_scope);
  decl->scope_ = scope;
  scopes_->top_func()->add(id->name_, decl);
  return decl;
}

void Parser::set_loc(Node *n, const BisonParser::location_type &loc) const {
  n->line_ = loc.begin.line;
  n->column_ = loc.begin.column;
  n->text_ = lexer.text(loc);
}

string Parser::pragma(const string &name) const {
  auto it = pragmas_.find(name);
  if (it == pragmas_.end()) return "main";
  return it->second;
}

}  // namespace cc
}  // namespace ebpf
