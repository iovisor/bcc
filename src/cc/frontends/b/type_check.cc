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

#include <set>
#include <algorithm>
#include "bcc_exception.h"
#include "type_check.h"
#include "lexer.h"

namespace ebpf {
namespace cc {

using std::for_each;
using std::set;

StatusTuple TypeCheck::visit_block_stmt_node(BlockStmtNode *n) {
  // enter scope
  if (n->scope_)
    scopes_->push_var(n->scope_);
  if (!n->stmts_.empty()) {
    for (auto it = n->stmts_.begin(); it != n->stmts_.end(); ++it)
      TRY2((*it)->accept(this));
  }

  if (n->scope_)
    scopes_->pop_var();
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_if_stmt_node(IfStmtNode *n) {
  TRY2(n->cond_->accept(this));
  //if (n->cond_->typeof_ != ExprNode::INTEGER)
  //  return mkstatus_(n, "If condition must be a numeric type");
  TRY2(n->true_block_->accept(this));
  if (n->false_block_) {
    TRY2(n->false_block_->accept(this));
  }
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_onvalid_stmt_node(OnValidStmtNode *n) {
  TRY2(n->cond_->accept(this));
  auto sdecl = static_cast<StructVariableDeclStmtNode*>(n->cond_->decl_);
  if (sdecl->storage_type_ != StructVariableDeclStmtNode::STRUCT_REFERENCE)
    return mkstatus_(n, "on_valid condition must be a reference type");
  TRY2(n->block_->accept(this));
  if (n->else_block_) {
    TRY2(n->else_block_->accept(this));
  }
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_switch_stmt_node(SwitchStmtNode *n) {
  TRY2(n->cond_->accept(this));
  if (n->cond_->typeof_ != ExprNode::INTEGER)
    return mkstatus_(n, "Switch condition must be a numeric type");
  TRY2(n->block_->accept(this));
  for (auto it = n->block_->stmts_.begin(); it != n->block_->stmts_.end(); ++it) {
    /// @todo check for duplicates
  }
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_case_stmt_node(CaseStmtNode *n) {
  if (n->value_) {
    TRY2(n->value_->accept(this));
    if (n->value_->typeof_ != ExprNode::INTEGER)
      return mkstatus_(n, "Switch condition must be a numeric type");
  }
  TRY2(n->block_->accept(this));
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_ident_expr_node(IdentExprNode *n) {
  n->decl_ = scopes_->current_var()->lookup(n->name_, SCOPE_GLOBAL);
  if (!n->decl_)
    return mkstatus_(n, "Variable %s lookup failed", n->c_str());

  n->typeof_ = ExprNode::UNKNOWN;
  if (n->sub_name_.empty()) {
    if (n->decl_->storage_type_ == VariableDeclStmtNode::INTEGER) {
      n->typeof_ = ExprNode::INTEGER;
      n->bit_width_ = n->decl_->bit_width_;
      n->flags_[ExprNode::WRITE] = true;
    } else if (n->decl_->is_struct()) {
      n->typeof_ = ExprNode::STRUCT;
      auto sdecl = static_cast<StructVariableDeclStmtNode*>(n->decl_);
      if (sdecl->struct_id_->scope_name_ == "proto") {
        n->struct_type_ = proto_scopes_->top_struct()->lookup(sdecl->struct_id_->name_, true);
        n->flags_[ExprNode::PROTO] = true;
      } else {
        n->struct_type_ = scopes_->top_struct()->lookup(sdecl->struct_id_->name_, true);
      }
      if (!n->struct_type_)
        return mkstatus_(n, "Type %s has not been declared", sdecl->struct_id_->full_name().c_str());
      n->bit_width_ = n->struct_type_->bit_width_;
    }
  } else {
    if (n->decl_->storage_type_ == VariableDeclStmtNode::INTEGER)
      return mkstatus_(n, "Subfield access not valid for numeric types");
    auto sdecl = static_cast<StructVariableDeclStmtNode*>(n->decl_);
    if (sdecl->struct_id_->scope_name_ == "proto") {
      n->struct_type_ = proto_scopes_->top_struct()->lookup(sdecl->struct_id_->name_, true);
      n->flags_[ExprNode::PROTO] = true;
    } else {
      n->struct_type_ = scopes_->top_struct()->lookup(sdecl->struct_id_->name_, true);
    }
    if (!n->struct_type_)
      return mkstatus_(n, "Type %s has not been declared", sdecl->struct_id_->full_name().c_str());
    n->sub_decl_ = n->struct_type_->field(n->sub_name_);

    if (!n->sub_decl_)
      return mkstatus_(n, "Access to invalid subfield %s.%s", n->c_str(), n->sub_name_.c_str());
    if (n->sub_decl_->storage_type_ != VariableDeclStmtNode::INTEGER)
      return mkstatus_(n, "Accessing non-numeric subfield %s.%s", n->c_str(), n->sub_name_.c_str());

    n->typeof_ = ExprNode::INTEGER;
    n->bit_width_ = n->sub_decl_->bit_width_;
    n->flags_[ExprNode::WRITE] = true;
  }
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_assign_expr_node(AssignExprNode *n) {
  /// @todo check lhs is assignable
  TRY2(n->lhs_->accept(this));
  if (n->lhs_->typeof_ == ExprNode::STRUCT) {
    TRY2(n->rhs_->accept(this));
    if (n->rhs_->typeof_ != ExprNode::STRUCT)
      return mkstatus_(n, "Right-hand side of assignment must be a struct");
  } else {
    if (n->lhs_->typeof_ != ExprNode::INTEGER)
      return mkstatus_(n, "Left-hand side of assignment must be a numeric type");
    if (!n->lhs_->flags_[ExprNode::WRITE])
      return mkstatus_(n, "Left-hand side of assignment is read-only");
    TRY2(n->rhs_->accept(this));
    if (n->rhs_->typeof_ != ExprNode::INTEGER)
      return mkstatus_(n, "Right-hand side of assignment must be a numeric type");
  }
  n->typeof_ = ExprNode::VOID;
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_packet_expr_node(PacketExprNode *n) {
  StructDeclStmtNode *struct_type = proto_scopes_->top_struct()->lookup(n->id_->name_, true);
  if (!struct_type)
    return mkstatus_(n, "Undefined packet header %s", n->id_->c_str());
  if (n->id_->sub_name_.empty()) {
    n->typeof_ = ExprNode::STRUCT;
    n->struct_type_ = struct_type;
  } else {
    VariableDeclStmtNode *sub_decl = struct_type->field(n->id_->sub_name_);
    if (!sub_decl)
      return mkstatus_(n, "Access to invalid subfield %s.%s", n->id_->c_str(), n->id_->sub_name_.c_str());
    n->typeof_ = ExprNode::INTEGER;
    if (n->is_ref())
      n->bit_width_ = 64;
    else
      n->bit_width_ = sub_decl->bit_width_;
  }
  n->flags_[ExprNode::WRITE] = true;
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_integer_expr_node(IntegerExprNode *n) {
  n->typeof_ = ExprNode::INTEGER;
  n->bit_width_ = n->bits_;
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_string_expr_node(StringExprNode *n) {
  n->typeof_ = ExprNode::STRING;
  n->flags_[ExprNode::IS_REF] = true;
  n->bit_width_ = n->val_.size() << 3;
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_binop_expr_node(BinopExprNode *n) {
  TRY2(n->lhs_->accept(this));
  if (n->lhs_->typeof_ != ExprNode::INTEGER)
    return mkstatus_(n, "Left-hand side of binary expression must be a numeric type");
  TRY2(n->rhs_->accept(this));
  if (n->rhs_->typeof_ != ExprNode::INTEGER)
    return mkstatus_(n, "Right-hand side of binary expression must be a numeric type");
  n->typeof_ = ExprNode::INTEGER;
  switch(n->op_) {
    case Tok::TCEQ:
    case Tok::TCNE:
    case Tok::TCLT:
    case Tok::TCLE:
    case Tok::TCGT:
    case Tok::TCGE:
      n->bit_width_ = 1;
    default:
      n->bit_width_ = std::max(n->lhs_->bit_width_, n->rhs_->bit_width_);
  }
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_unop_expr_node(UnopExprNode *n) {
  TRY2(n->expr_->accept(this));
  if (n->expr_->typeof_ != ExprNode::INTEGER)
    return mkstatus_(n, "Unary operand must be a numeric type");
  n->copy_type(*n->expr_);
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_bitop_expr_node(BitopExprNode *n) {
  if (n->expr_->typeof_ != ExprNode::INTEGER)
    return mkstatus_(n, "Bitop [] can only operate on numeric types");
  n->typeof_ = ExprNode::INTEGER;
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_goto_expr_node(GotoExprNode *n) {
  //n->id_->accept(this);
  n->typeof_ = ExprNode::VOID;
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_return_expr_node(ReturnExprNode *n) {
  TRY2(n->expr_->accept(this));
  n->typeof_ = ExprNode::VOID;
  return StatusTuple(0);
}

StatusTuple TypeCheck::expect_method_arg(MethodCallExprNode *n, size_t num, size_t num_def_args = 0) {
  if (num_def_args == 0) {
    if (n->args_.size() != num)
      return mkstatus_(n, "%s expected %d argument%s, %zu given", n->id_->sub_name_.c_str(),
                      num, num == 1 ? "" : "s", n->args_.size());
  } else {
    if (n->args_.size() < num - num_def_args || n->args_.size() > num)
      return mkstatus_(n, "%s expected %d argument%s (%d default), %zu given", n->id_->sub_name_.c_str(),
                      num, num == 1 ? "" : "s", num_def_args, n->args_.size());
  }
  return StatusTuple(0);
}

StatusTuple TypeCheck::check_lookup_method(MethodCallExprNode *n) {
  auto table = scopes_->top_table()->lookup(n->id_->name_);
  if (!table)
    return mkstatus_(n, "Unknown table name %s", n->id_->c_str());
  TRY2(expect_method_arg(n, 2, 1));
  if (table->type_id()->name_ == "LPM")
    return mkstatus_(n, "LPM unsupported");
  if (n->block_->scope_) {
    auto result = make_unique<StructVariableDeclStmtNode>(table->leaf_id()->copy(), make_unique<IdentExprNode>("_result"),
                                                          VariableDeclStmtNode::STRUCT_REFERENCE);
    n->block_->scope_->add("_result", result.get());
    n->block_->stmts_.insert(n->block_->stmts_.begin(), move(result));
  }
  return StatusTuple(0);
}

StatusTuple TypeCheck::check_update_method(MethodCallExprNode *n) {
  auto table = scopes_->top_table()->lookup(n->id_->name_);
  if (!table)
    return mkstatus_(n, "Unknown table name %s", n->id_->c_str());
  if (table->type_id()->name_ == "FIXED_MATCH" || table->type_id()->name_ == "INDEXED")
    TRY2(expect_method_arg(n, 2));
  else if (table->type_id()->name_ == "LPM")
    TRY2(expect_method_arg(n, 3));
  return StatusTuple(0);
}

StatusTuple TypeCheck::check_delete_method(MethodCallExprNode *n) {
  auto table = scopes_->top_table()->lookup(n->id_->name_);
  if (!table)
    return mkstatus_(n, "Unknown table name %s", n->id_->c_str());
  if (table->type_id()->name_ == "FIXED_MATCH" || table->type_id()->name_ == "INDEXED")
    TRY2(expect_method_arg(n, 1));
  else if (table->type_id()->name_ == "LPM")
    {}
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_method_call_expr_node(MethodCallExprNode *n) {
  // be sure to visit those child nodes ASAP, so their properties can
  // be propagated up to this node and be ready to be used
  for (auto it = n->args_.begin(); it != n->args_.end(); ++it) {
    TRY2((*it)->accept(this));
  }

  n->typeof_ = ExprNode::VOID;
  if (n->id_->sub_name_.size()) {
    if (n->id_->sub_name_ == "lookup") {
      TRY2(check_lookup_method(n));
    } else if (n->id_->sub_name_ == "update") {
      TRY2(check_update_method(n));
    } else if (n->id_->sub_name_ == "delete") {
      TRY2(check_delete_method(n));
    } else if (n->id_->sub_name_ == "rewrite_field" && n->id_->name_ == "pkt") {
      TRY2(expect_method_arg(n, 2));
      n->args_[0]->flags_[ExprNode::IS_LHS] = true;
    }
  } else if (n->id_->name_ == "log") {
    if (n->args_.size() < 1)
      return mkstatus_(n, "%s expected at least 1 argument", n->id_->c_str());
    if (n->args_[0]->typeof_ != ExprNode::STRING)
      return mkstatus_(n, "%s expected a string for argument 1", n->id_->c_str());
    n->typeof_ = ExprNode::INTEGER;
    n->bit_width_ = 32;
  } else if (n->id_->name_ == "atomic_add") {
    TRY2(expect_method_arg(n, 2));
    n->typeof_ = ExprNode::INTEGER;
    n->bit_width_ = n->args_[0]->bit_width_;
    n->args_[0]->flags_[ExprNode::IS_LHS] = true;
  } else if (n->id_->name_ == "incr_cksum") {
    TRY2(expect_method_arg(n, 4, 1));
    n->typeof_ = ExprNode::INTEGER;
    n->bit_width_ = 16;
  } else if (n->id_->name_ == "sizeof") {
    TRY2(expect_method_arg(n, 1));
    n->typeof_ = ExprNode::INTEGER;
    n->bit_width_ = 32;
  } else if (n->id_->name_ == "get_usec_time") {
     TRY2(expect_method_arg(n, 0));
     n->typeof_ = ExprNode::INTEGER;
     n->bit_width_ = 64;
  }

  if (!n->block_->stmts_.empty()) {
    if (n->id_->sub_name_ != "update" && n->id_->sub_name_ != "lookup")
      return mkstatus_(n, "%s does not allow trailing block statements", n->id_->full_name().c_str());
    TRY2(n->block_->accept(this));
  }
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_table_index_expr_node(TableIndexExprNode *n) {
  n->table_ = scopes_->top_table()->lookup(n->id_->name_);
  if (!n->table_) return mkstatus_(n, "Unknown table name %s", n->id_->c_str());
  TRY2(n->index_->accept(this));
  if (n->index_->struct_type_ != n->table_->key_type_)
    return mkstatus_(n, "Key to table %s lookup must be of type %s", n->id_->c_str(), n->table_->key_id()->c_str());

  if (n->sub_) {
    n->sub_decl_ = n->table_->leaf_type_->field(n->sub_->name_);
    if (!n->sub_decl_)
      return mkstatus_(n, "Field %s is not a member of %s", n->sub_->c_str(), n->table_->leaf_id()->c_str());
    n->typeof_ = ExprNode::INTEGER;
  } else {
    n->typeof_ = ExprNode::STRUCT;
    n->flags_[ExprNode::IS_REF] = true;
    n->struct_type_ = n->table_->leaf_type_;
  }
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_expr_stmt_node(ExprStmtNode *n) {
  TRY2(n->expr_->accept(this));
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_struct_variable_decl_stmt_node(StructVariableDeclStmtNode *n) {
  //TRY2(n->struct_id_->accept(this));
  //TRY2(n->id_->accept(this));
  if (!n->init_.empty()) {
    StructDeclStmtNode *type;
    if (n->struct_id_->scope_name_ == "proto")
      type = proto_scopes_->top_struct()->lookup(n->struct_id_->name_, true);
    else
      type = scopes_->top_struct()->lookup(n->struct_id_->name_, true);

    if (!type)
      return mkstatus_(n, "type %s does not exist", n->struct_id_->full_name().c_str());

    // init remaining fields to 0
    set<string> used;
    for (auto i = n->init_.begin(); i != n->init_.end(); ++i) {
      auto asn = static_cast<AssignExprNode*>(i->get());
      auto id = static_cast<IdentExprNode *>(asn->lhs_.get());
      used.insert(id->sub_name_);
    }
    for (auto f = type->stmts_.begin(); f != type->stmts_.end(); ++f) {
      if (used.find((*f)->id_->name_) == used.end()) {
        auto id = make_unique<IdentExprNode>(n->id_->name_);
        id->append_dot((*f)->id_->name_);
        n->init_.push_back(make_unique<AssignExprNode>(move(id), make_unique<IntegerExprNode>("0")));
      }
    }

    for (auto it = n->init_.begin(); it != n->init_.end(); ++it) {
      TRY2((*it)->accept(this));
    }
  }
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_integer_variable_decl_stmt_node(IntegerVariableDeclStmtNode *n) {
  //TRY2(n->id_->accept(this));
  if (!n->init_.empty()) {
    TRY2(n->init_[0]->accept(this));
  }
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_struct_decl_stmt_node(StructDeclStmtNode *n) {
  //TRY2(n->id_->accept(this));
  for (auto it = n->stmts_.begin(); it != n->stmts_.end(); ++it) {
    TRY2((*it)->accept(this));
  }
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_parser_state_stmt_node(ParserStateStmtNode *n) {
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_state_decl_stmt_node(StateDeclStmtNode *n) {
  if (!n->id_) {
    return StatusTuple(0);
  }
  auto s1 = proto_scopes_->top_state()->lookup(n->id_->name_, true);
  if (s1) {
    const string &name = n->id_->name_;
    auto offset_var = make_unique<IntegerVariableDeclStmtNode>(make_unique<IdentExprNode>("$" + name), "64");
    offset_var->init_.push_back(make_unique<AssignExprNode>(offset_var->id_->copy(), make_unique<IntegerExprNode>("0")));
    scopes_->current_var()->add("$" + name, offset_var.get());
    s1->subs_[0].block_->scope_->add("$" + name, offset_var.get());
    n->init_.push_back(move(offset_var));

    n->parser_ = ParserStateStmtNode::make(n->id_);
    n->parser_->next_state_ = s1->subs_[0].block_.get();
    n->parser_->scope_id_ = n->scope_id_;

    auto p = proto_scopes_->top_struct()->lookup(n->id_->name_, true);
    if (!p) return mkstatus_(n, "unable to find struct decl for parser state %s", n->id_->full_name().c_str());

    // $proto = parsed_bytes; parsed_bytes += sizeof($proto);
    auto asn1 = make_unique<AssignExprNode>(make_unique<IdentExprNode>("$" + n->id_->name_),
                                            make_unique<IdentExprNode>("parsed_bytes"));
    n->init_.push_back(make_unique<ExprStmtNode>(move(asn1)));
    auto add_expr = make_unique<BinopExprNode>(make_unique<IdentExprNode>("parsed_bytes"), Tok::TPLUS,
                                               make_unique<IntegerExprNode>(std::to_string(p->bit_width_ >> 3), 64));
    auto asn2 = make_unique<AssignExprNode>(make_unique<IdentExprNode>("parsed_bytes"), move(add_expr));
    n->init_.push_back(make_unique<ExprStmtNode>(move(asn2)));
  }

  for (auto it = n->init_.begin(); it != n->init_.end(); ++it) {
    TRY2((*it)->accept(this));
  }

  for (auto it = n->subs_.begin(); it != n->subs_.end(); ++it) {
    scopes_->push_state(it->scope_);

    TRY2(it->block_->accept(this));

    if (s1) {
      if (it->id_->name_ == "") {
        it->parser_ = ParserStateStmtNode::make(it->id_);
        it->parser_->next_state_ = s1->subs_[0].block_.get();
        it->parser_->scope_id_ = n->scope_id_ + n->id_->name_ + "_";
      } else if (auto s2 = proto_scopes_->top_state()->lookup(it->id_->name_, true)) {
        it->parser_ = ParserStateStmtNode::make(it->id_);
        it->parser_->next_state_ = s2->subs_[0].block_.get();
        it->parser_->scope_id_ = n->scope_id_ + n->id_->name_ + "_";
      }

      if (it->parser_) {
        TRY2(it->parser_->accept(this));
      }
    }

    scopes_->pop_state();
  }
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_match_decl_stmt_node(MatchDeclStmtNode *n) {
  //TRY2(n->id_->accept(this));
  for (auto it = n->formals_.begin(); it != n->formals_.end(); ++it) {
    TRY2((*it)->accept(this));
  }
  TRY2(n->block_->accept(this));
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_miss_decl_stmt_node(MissDeclStmtNode *n) {
  //TRY2(n->id_->accept(this));
  for (auto it = n->formals_.begin(); it != n->formals_.end(); ++it) {
    TRY2((*it)->accept(this));
  }
  TRY2(n->block_->accept(this));
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_failure_decl_stmt_node(FailureDeclStmtNode *n) {
  //TRY2(n->id_->accept(this));
  for (auto it = n->formals_.begin(); it != n->formals_.end(); ++it) {
    TRY2((*it)->accept(this));
  }
  TRY2(n->block_->accept(this));
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_table_decl_stmt_node(TableDeclStmtNode *n) {
  n->key_type_ = scopes_->top_struct()->lookup(n->key_id()->name_, true);
  if (!n->key_type_)
    return mkstatus_(n, "Table key type %s undefined", n->key_id()->c_str());
  n->key_id()->bit_width_ = n->key_type_->bit_width_;
  n->leaf_type_ = scopes_->top_struct()->lookup(n->leaf_id()->name_, true);
  if (!n->leaf_type_)
    return mkstatus_(n, "Table leaf type %s undefined", n->leaf_id()->c_str());
  n->leaf_id()->bit_width_ = n->leaf_type_->bit_width_;
  if (n->type_id()->name_ == "INDEXED" && n->policy_id()->name_ != "AUTO") {
    fprintf(stderr, "Table %s is INDEXED, policy should be AUTO\n", n->id_->c_str());
    n->policy_id()->name_ = "AUTO";
  }
  if (n->policy_id()->name_ != "AUTO" && n->policy_id()->name_ != "NONE")
    return mkstatus_(n, "Unsupported policy type %s", n->policy_id()->c_str());
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit_func_decl_stmt_node(FuncDeclStmtNode *n) {
  for (auto it = n->formals_.begin(); it != n->formals_.end(); ++it) {
    VariableDeclStmtNode *var = it->get();
    TRY2(var->accept(this));
    if (var->is_struct()) {
      if (!var->is_pointer())
        return mkstatus_(n, "Only struct references allowed in function definitions");
    }
  }
  scopes_->push_state(n->scope_);
  TRY2(n->block_->accept(this));
  scopes_->pop_state();
  return StatusTuple(0);
}

StatusTuple TypeCheck::visit(Node *root) {
  BlockStmtNode *b = static_cast<BlockStmtNode*>(root);

  scopes_->set_current(scopes_->top_state());
  scopes_->set_current(scopes_->top_var());

  // // packet data in bpf socket
  // if (scopes_->top_struct()->lookup("_skbuff", true)) {
  //   return StatusTuple(-1, "_skbuff already defined");
  // }
  // auto skb_type = make_unique<StructDeclStmtNode>(make_unique<IdentExprNode>("_skbuff"));
  // scopes_->top_struct()->add("_skbuff", skb_type.get());
  // b->stmts_.push_back(move(skb_type));

  // if (scopes_->current_var()->lookup("skb", true)) {
  //   return StatusTuple(-1, "skb already defined");
  // }
  // auto skb = make_unique<StructVariableDeclStmtNode>(make_unique<IdentExprNode>("_skbuff"),
  //                                                    make_unique<IdentExprNode>("skb"));
  // skb->storage_type_ = VariableDeclStmtNode::STRUCT_REFERENCE;
  // scopes_->current_var()->add("skb", skb.get());
  // b->stmts_.push_back(move(skb));

  // offset counter
  auto parsed_bytes = make_unique<IntegerVariableDeclStmtNode>(
                        make_unique<IdentExprNode>("parsed_bytes"), "64");
  parsed_bytes->init_.push_back(make_unique<AssignExprNode>(parsed_bytes->id_->copy(), make_unique<IntegerExprNode>("0")));
  scopes_->current_var()->add("parsed_bytes", parsed_bytes.get());
  b->stmts_.push_back(move(parsed_bytes));

  TRY2(b->accept(this));

  if (!errors_.empty()) {
    for (auto it = errors_.begin(); it != errors_.end(); ++it) {
      fprintf(stderr, "%s\n", it->c_str());
    }
    return StatusTuple(-1, errors_.begin()->c_str());
  }
  return StatusTuple(0);
}

}  // namespace cc
}  // namespace ebpf
