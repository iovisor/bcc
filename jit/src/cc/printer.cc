/*
 * =====================================================================
 * Copyright (c) 2012, PLUMgrid, http://plumgrid.com
 *
 * This source is subject to the PLUMgrid License.
 * All rights reserved.
 *
 * THIS CODE AND INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF
 * ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 * PLUMgrid confidential information, delete if you are not the
 * intended recipient.
 *
 * =====================================================================
 */

#include "cc/printer.h"
#include "cc/lexer.h"
#include "exception.h"

namespace ebpf {
namespace cc {

void Printer::print_indent() {
  fprintf(out_, "%*s", indent_, "");
}

StatusTuple Printer::visit_block_stmt_node(BlockStmtNode* n) {
  fprintf(out_, "{\n");

  TRY2(n->ver_.accept(this));
  if (!n->stmts_.empty()) {
    ++indent_;
    for (auto it = n->stmts_.begin(); it != n->stmts_.end(); ++it) {
      print_indent();
      TRY2((*it)->accept(this));
      fprintf(out_, "\n");
    }
    --indent_;
  }
  fprintf(out_, "%*s}", indent_, "");
  return mkstatus(0);
}

StatusTuple Printer::visit_version_stmt_node(VersionStmtNode* n) {
  uint32_t version;
  version = MAKE_VERSION(n->major_, n->minor_, n->rev_);
  fprintf(out_, "static const uint32_t  plumlet_version   __attribute__"
      "((section (\".version\"), used)) = 0x%x;\n", version);
  return mkstatus(0);
}

StatusTuple Printer::visit_if_stmt_node(IfStmtNode* n) {
  fprintf(out_, "if ");
  TRY2(n->cond_->accept(this));
  fprintf(out_, " ");
  TRY2(n->true_block_->accept(this));
  if (n->false_block_) {
    fprintf(out_, " else ");
    TRY2(n->false_block_->accept(this));
  }
  return mkstatus(0);
}

StatusTuple Printer::visit_onvalid_stmt_node(OnValidStmtNode* n) {
  fprintf(out_, "if ");
  TRY2(n->cond_->accept(this));
  fprintf(out_, " ");
  TRY2(n->block_->accept(this));
  if (n->else_block_) {
    fprintf(out_, " else ");
    TRY2(n->else_block_->accept(this));
  }
  return mkstatus(0);
}

StatusTuple Printer::visit_switch_stmt_node(SwitchStmtNode* n) {
  fprintf(out_, "switch (");
  TRY2(n->cond_->accept(this));
  fprintf(out_, ") ");
  TRY2(n->block_->accept(this));
  return mkstatus(0);
}

StatusTuple Printer::visit_case_stmt_node(CaseStmtNode* n) {
  if (n->value_) {
    fprintf(out_, "case ");
    TRY2(n->value_->accept(this));
  } else {
    fprintf(out_, "default");
  }
  TRY2(n->block_->accept(this));
  return mkstatus(0);
}

StatusTuple Printer::visit_ident_expr_node(IdentExprNode* n) {
  if (n->scope_name_.size()) {
    fprintf(out_, "%s::", n->scope_name_.c_str());
  }
  fprintf(out_, "%s", n->name_.c_str());
  if (n->sub_name_.size()) {
    fprintf(out_, ".%s", n->sub_name_.c_str());
  }
  return mkstatus(0);
}

StatusTuple Printer::visit_assign_expr_node(AssignExprNode* n) {
  TRY2(n->id_->accept(this));
  fprintf(out_, " = ");
  TRY2(n->rhs_->accept(this));
  return mkstatus(0);
}

StatusTuple Printer::visit_packet_expr_node(PacketExprNode* n) {
  fprintf(out_, "$");
  TRY2(n->id_->accept(this));
  return mkstatus(0);
}

StatusTuple Printer::visit_integer_expr_node(IntegerExprNode* n) {
  fprintf(out_, "%s:%zu", n->val_.c_str(), n->bits_);
  return mkstatus(0);
}

StatusTuple Printer::visit_binop_expr_node(BinopExprNode* n) {
  TRY2(n->lhs_->accept(this));
  fprintf(out_, "%d", n->op_);
  TRY2(n->rhs_->accept(this));
  return mkstatus(0);
}

StatusTuple Printer::visit_unop_expr_node(UnopExprNode* n) {
  const char* s = "";
  switch (n->op_) {
    case Tok::TNOT: s = "!"; break;
    case Tok::TCMPL: s = "~"; break;
    case Tok::TMOD:  s = "%"; break;
    default: {}
  }
  fprintf(out_, "%s", s);
  TRY2(n->expr_->accept(this));
  return mkstatus(0);
}

StatusTuple Printer::visit_bitop_expr_node(BitopExprNode* n) {

  return mkstatus(0);
}

StatusTuple Printer::visit_return_expr_node(ReturnExprNode* n) {
  fprintf(out_, "return ");
  TRY2(n->expr_->accept(this));
  return mkstatus(0);
}

StatusTuple Printer::visit_goto_expr_node(GotoExprNode* n) {
  const char* s = n->is_continue_ ? "continue " : "goto ";
  fprintf(out_, "%s", s);
  TRY2(n->id_->accept(this));
  return mkstatus(0);
}

StatusTuple Printer::visit_method_call_expr_node(MethodCallExprNode* n) {
  TRY2(n->id_->accept(this));
  fprintf(out_, "(");
  for (auto it = n->args_.begin(); it != n->args_.end(); ++it) {
    TRY2((*it)->accept(this));
    if (it + 1 != n->args_.end()) {
      fprintf(out_, ", ");
    }
  }
  fprintf(out_, ")");
  if (!n->block_->stmts_.empty()) {
    fprintf(out_, " {\n");
    ++indent_;
    for (auto it = n->block_->stmts_.begin(); it != n->block_->stmts_.end(); ++it) {
      print_indent();
      TRY2((*it)->accept(this));
      fprintf(out_, "\n");
    }
    --indent_;
    fprintf(out_, "%*s}", indent_, "");
  }
  return mkstatus(0);
}

StatusTuple Printer::visit_expr_stmt_node(ExprStmtNode* n) {
  TRY2(n->expr_->accept(this));
  return mkstatus(0);
}

StatusTuple Printer::visit_struct_variable_decl_stmt_node(StructVariableDeclStmtNode* n) {
  fprintf(out_, "var ");
  TRY2(n->struct_id_->accept(this));
  fprintf(out_, " ");
  TRY2(n->id_->accept(this));
  if (!n->init_.empty()) {
    fprintf(out_, "{");
    for (auto it = n->init_.begin(); it != n->init_.end(); ++it) {
      TRY2((*it)->accept(this));
      if (it + 1 != n->init_.end()) {
        fprintf(out_, ", ");
      }
    }
    fprintf(out_, "}");
  }
  return mkstatus(0);
}

StatusTuple Printer::visit_integer_variable_decl_stmt_node(IntegerVariableDeclStmtNode* n) {
  fprintf(out_, "var ");
  TRY2(n->id_->accept(this));
  fprintf(out_, ":%zu", n->bit_width_);
  if (!n->init_.empty()) {
    fprintf(out_, "; ");
    TRY2(n->init_[0]->accept(this));
  }
  return mkstatus(0);
}

StatusTuple Printer::visit_struct_decl_stmt_node(StructDeclStmtNode* n) {
  fprintf(out_, "struct ");
  TRY2(n->id_->accept(this));
  fprintf(out_, " {\n");
  ++indent_;
  for (auto it = n->stmts_.begin(); it != n->stmts_.end(); ++it) {
    print_indent();
    TRY2((*it)->accept(this));
    fprintf(out_, "\n");
  }
  --indent_;
  fprintf(out_, "%*s}", indent_, "");
  return mkstatus(0);
}

StatusTuple Printer::visit_timer_decl_stmt_node(TimerDeclStmtNode* n) {
  if (!n->id_) {
    return mkstatus(0);
  }
  fprintf(out_, "timer ");
  TRY2(n->id_->accept(this));
  return mkstatus(0);
}

StatusTuple Printer::visit_state_decl_stmt_node(StateDeclStmtNode* n) {
  if (!n->id_) {
    return mkstatus(0);
  }
  fprintf(out_, "state ");
  TRY2(n->id_->accept(this));
  //if (!n->id2_) {
  //  fprintf(out_, ", * ");
  //} else {
  //  fprintf(out_, ", ");
  //  TRY2(n->id2_->accept(this));
  //}
  //TRY2(n->block_->accept(this));
  return mkstatus(0);
}

StatusTuple Printer::visit_parser_state_stmt_node(ParserStateStmtNode* n) {
  return mkstatus(0);
}

StatusTuple Printer::visit_match_decl_stmt_node(MatchDeclStmtNode* n) {
  fprintf(out_, "on_match ");
  TRY2(n->id_->accept(this));
  fprintf(out_, " (");
  for (auto it = n->formals_.begin(); it != n->formals_.end(); ++it) {
    TRY2((*it)->accept(this));
    if (it + 1 != n->formals_.end()) {
      fprintf(out_, ", ");
    }
  }
  fprintf(out_, ") ");
  TRY2(n->block_->accept(this));
  return mkstatus(0);
}

StatusTuple Printer::visit_miss_decl_stmt_node(MissDeclStmtNode* n) {
  fprintf(out_, "on_miss ");
  TRY2(n->id_->accept(this));
  fprintf(out_, " (");
  for (auto it = n->formals_.begin(); it != n->formals_.end(); ++it) {
    TRY2((*it)->accept(this));
    if (it + 1 != n->formals_.end()) {
      fprintf(out_, ", ");
    }
  }
  fprintf(out_, ") ");
  TRY2(n->block_->accept(this));
  return mkstatus(0);
}

StatusTuple Printer::visit_failure_decl_stmt_node(FailureDeclStmtNode* n) {
  fprintf(out_, "on_failure ");
  TRY2(n->id_->accept(this));
  fprintf(out_, " (");
  for (auto it = n->formals_.begin(); it != n->formals_.end(); ++it) {
    TRY2((*it)->accept(this));
    if (it + 1 != n->formals_.end()) {
      fprintf(out_, ", ");
    }
  }
  fprintf(out_, ") ");
  TRY2(n->block_->accept(this));
  return mkstatus(0);
}

StatusTuple Printer::visit_table_decl_stmt_node(TableDeclStmtNode* n) {
  TRY2(n->table_type_->accept(this));
  fprintf(out_, "<");
  for (auto it = n->templates_.begin(); it != n->templates_.end(); ++it) {
    TRY2((*it)->accept(this));
    if (it + 1 != n->templates_.end()) {
      fprintf(out_, ", ");
    }
  }
  fprintf(out_, "> ");
  TRY2(n->id_->accept(this));
  fprintf(out_, "(%zu)", n->size_);
  return mkstatus(0);
}

}  // namespace cc
}  // namespace ebpf
