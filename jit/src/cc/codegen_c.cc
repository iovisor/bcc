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

#include <set>
#include <algorithm>
#include <sstream>
#include <assert.h>
#include "exception.h"
#include "cc/codegen_c.h"
#include "cc/lexer.h"
#include "cc/type_helper.h"

namespace ebpf {
namespace cc {

using std::set;
using std::for_each;
using std::pair;
using std::stringstream;

template <typename... Args>
void CodegenC::emitln(const char *fmt, Args&&... params) {
  fprintf(out_, fmt, std::forward<Args>(params)...);
  fprintf(out_, "\n%*s", indent_ * 2, "");
}
void CodegenC::emitln(const char *s) {
  fprintf(out_, "%s", s);
  fprintf(out_, "\n%*s", indent_ * 2, "");
}

template <typename... Args>
void CodegenC::emit(const char *fmt, Args&&... params) {
  fprintf(out_, fmt, std::forward<Args>(params)...);
}
void CodegenC::emit(const char *s) {
  fprintf(out_, "%s", s);
}

template <typename... Args>
void CodegenC::lnemit(const char *fmt, Args&&... params) {
  fprintf(out_, "\n%*s", indent_ * 2, "");
  fprintf(out_, fmt, std::forward<Args>(params)...);
}
void CodegenC::lnemit(const char *s) {
  fprintf(out_, "\n%*s", indent_ * 2, "");
  fprintf(out_, "%s", s);
}

void CodegenC::indent() {
  fprintf(out_, "%*s", indent_ * 2, "");
}

void CodegenC::emit_comment(Node* n) {
  // if (!n->text_.empty()) {
  //   emitln("/* %s */", n->text_.c_str());
  // }
}

void CodegenC::visit_block_stmt_node(BlockStmtNode* n) {

  ++indent_;
  emit("{");

  // enter scope
  auto scope = scopes_->current_var();
  if (n->scope_) {
    scopes_->set_current(n->scope_);
  }


  if (!n->stmts_.empty()) {
    for (auto it = n->stmts_.begin(); it != n->stmts_.end(); ++it) {
      emitln("");
      (*it)->accept(this);
    }
  }
  // exit scope
  scopes_->set_current(scope);

  --indent_;
  emitln("");
  emit("}");
}

void CodegenC::visit_version_stmt_node(VersionStmtNode* n) {
  uint32_t version;
  version = MAKE_VERSION(n->major_, n->minor_, n->rev_);
  emit("static const uint32_t  plumlet_version   __attribute__"
      "((section (\".version\"), used)) = 0x%x;\n", version);
}

void CodegenC::visit_if_stmt_node(IfStmtNode* n) {
  emit_comment(n);
  emit("if (");
  n->cond_->accept(this);
  emit(") ");
  n->true_block_->accept(this);
  if (n->false_block_) {
    emit(" else ");
    n->false_block_->accept(this);
  }
}

void CodegenC::visit_onvalid_stmt_node(OnValidStmtNode* n) {
  auto sdecl = static_cast<StructVariableDeclStmtNode*>(n->cond_->decl_);
  emit_comment(n);
  // cheat a little not using n->cond_->accept(this) to prevent the dereference
  emit("if (%s%s) ", sdecl->scope_id(), sdecl->id_->c_str());
  n->block_->accept(this);
  if (n->else_block_) {
    emit(" else ");
    n->else_block_->accept(this);
  }
}

void CodegenC::visit_switch_stmt_node(SwitchStmtNode* n) {
  emit_comment(n);
  emit("switch (");
  n->cond_->accept(this);
  emit(") ");
  n->block_->accept(this);
}

void CodegenC::visit_case_stmt_node(CaseStmtNode* n) {
  if (n->value_) {
    emit("case ");
    n->value_->accept(this);
  } else {
    emit("default");
  }
  emit(": ");
  ++indent_;
  n->block_->accept(this);
  emitln("");
  emit("break;");
  --indent_;
}

void CodegenC::visit_ident_expr_node(IdentExprNode* n) {
  if (!n->decl_)
    throw CompilerException("variable lookup failed: %s", n->name_.c_str());
  if (n->decl_->storage_type_ == VariableDeclStmtNode::STRUCT_REFERENCE) {
    if (n->sub_name_.size()) {
      if (n->bitop_) {
        // ident is holding a host endian number, don't use dext
        if (n->flags_[ExprNode::IS_LHS]) {
          emit("%s%s->%s", n->decl_->scope_id(), n->c_str(), n->sub_name_.c_str());
        } else {
          emit("(((%s%s->%s) >> %d) & (((%s)1 << %d) - 1))", n->decl_->scope_id(), n->c_str(), n->sub_name_.c_str(),
              n->bitop_->bit_offset_, bits_to_uint(n->bitop_->bit_width_ + 1), n->bitop_->bit_width_);
        }
      } else {
        if (n->struct_type_->id_->name_ == "_Packet" && n->sub_name_.substr(0, 3) == "arg") {
          // convert arg1~arg8 into args[0]~args[7] assuming type_check verified the range already
          auto arg_num = stoi(n->sub_name_.substr(3, 3));
          if (arg_num < 5) {
            emit("%s%s->args_lo[%d]", n->decl_->scope_id(), n->c_str(), arg_num - 1);
          } else {
            emit("%s%s->args_hi[%d]", n->decl_->scope_id(), n->c_str(), arg_num - 5);
          }
        } else {
          emit("%s%s->%s", n->decl_->scope_id(), n->c_str(), n->sub_name_.c_str());
        }
      }
    } else {
      emit("*%s%s", n->decl_->scope_id(), n->c_str());
    }
  } else {
    if (n->sub_name_.size()) {
      emit("%s%s.%s", n->decl_->scope_id(), n->c_str(), n->sub_name_.c_str());
    } else {
      if (n->bitop_) {
        // ident is holding a host endian number, don't use dext
        if (n->flags_[ExprNode::IS_LHS]) {
          assert(0);
        } else {
          emit("(((%s%s) >> %d) & (((%s)1 << %d) - 1))", n->decl_->scope_id(), n->c_str(),
               n->bitop_->bit_offset_, bits_to_uint(n->bitop_->bit_width_ + 1), n->bitop_->bit_width_);
        }
      } else {
        emit("%s%s", n->decl_->scope_id(), n->c_str());
      }
    }
  }
}

void CodegenC::visit_assign_expr_node(AssignExprNode* n) {
  if (n->bitop_) {
    n->id_->accept(this);
    emit(" = (");
    n->id_->accept(this);
    emit(" & ~((((%s)1 << %d) - 1) << %d)) | (", bits_to_uint(n->id_->bit_width_),
         n->bitop_->bit_width_, n->bitop_->bit_offset_);
    n->rhs_->accept(this);
    emit(" << %d)", n->bitop_->bit_offset_);
  } else {
    if (n->id_->flags_[ExprNode::PROTO]) {
      auto f = n->id_->struct_type_->field(n->id_->sub_name_);
      emit("bpf_dins(%s%s + %zu, %zu, %zu, ", n->id_->decl_->scope_id(), n->id_->c_str(),
           f->bit_offset_ >> 3, f->bit_offset_ & 0x7, f->bit_width_);
      n->rhs_->accept(this);
      emit(")");
    } else {
      n->id_->accept(this);
      emit(" = ");
      n->rhs_->accept(this);
    }
  }
}

void CodegenC::visit_packet_expr_node(PacketExprNode* n) {
  auto p = proto_scopes_->top_struct()->lookup(n->id_->name_, true);
  if (p) {
    auto f = p->field(n->id_->sub_name_);
    if (f) {
      size_t bit_offset = f->bit_offset_;
      size_t bit_width = f->bit_width_;
      if (n->bitop_) {
        bit_offset += f->bit_width_ - (n->bitop_->bit_offset_ + n->bitop_->bit_width_);
        bit_width = std::min(bit_width - n->bitop_->bit_offset_, n->bitop_->bit_width_);
      }
      if (n->flags_[ExprNode::IS_LHS])
        emit("bpf_dins_pkt(pkt, %s + %zu, %zu, %zu, ", n->id_->c_str(), bit_offset >> 3, bit_offset & 0x7, bit_width);
      else
        emit("bpf_dext_pkt(pkt, %s + %zu, %zu, %zu)", n->id_->c_str(), bit_offset >> 3, bit_offset & 0x7, bit_width);
    } else {
      emit("pkt->start + pkt->offset + %s", n->id_->c_str());
    }
  }
}

void CodegenC::visit_integer_expr_node(IntegerExprNode* n) {
  emit("%s", n->val_.c_str());
}

void CodegenC::visit_binop_expr_node(BinopExprNode* n) {
  n->lhs_->accept(this);
  switch (n->op_) {
    case Tok::TCEQ: emit(" == "); break;
    case Tok::TCNE: emit(" != "); break;
    case Tok::TXOR: emit(" ^ "); break;
    case Tok::TAND: emit(" && "); break;
    case Tok::TOR: emit(" || "); break;
    case Tok::TMOD: emit("%");  break;
    case Tok::TCLT: emit(" < "); break;
    case Tok::TCLE: emit(" <= "); break;
    case Tok::TCGT: emit(" > "); break;
    case Tok::TCGE: emit(" >= "); break;
    case Tok::TPLUS: emit(" + "); break;
    case Tok::TMINUS: emit(" - "); break;
    case Tok::TLAND: emit(" & "); break;
    case Tok::TLOR: emit(" | "); break;
    default: emit(" ?%d? ", n->op_); break;
  }
  n->rhs_->accept(this);
}

void CodegenC::visit_unop_expr_node(UnopExprNode* n) {
  const char* s = "";
  switch (n->op_) {
    case Tok::TNOT: s = "!"; break;
    case Tok::TCMPL: s = "~"; break;
    default: {}
  }
  emit("%s", s);
  n->expr_->accept(this);
}

void CodegenC::visit_bitop_expr_node(BitopExprNode* n) {
}

void CodegenC::visit_goto_expr_node(GotoExprNode* n) {
  if (n->id_->name_ == "DONE") {
    for (auto ii = free_instructions_.rbegin(); ii != free_instructions_.rend(); ++ii)
      for (auto jj = ii->rbegin(); jj != ii->rend(); ++jj)
        emitln("%s;", jj->c_str());
    emit("goto DONE");
    return;
  }
  string jump_label;
  // when dealing with multistates, goto statements may be overridden
  auto rewrite_it = proto_rewrites_.find(n->id_->full_name());
  auto default_it = proto_rewrites_.find("");
  if (rewrite_it != proto_rewrites_.end()) {
    jump_label = rewrite_it->second;
  } else if (default_it != proto_rewrites_.end()) {
    jump_label = default_it->second;
  } else {
    auto state = scopes_->current_state()->lookup(n->id_->full_name(), false);
    if (state) {
      jump_label = state->scoped_name();
      if (n->is_continue_) {
        jump_label += "_continue";
      }
    } else {
      state = scopes_->current_state()->lookup("EOP", false);
      if (state) {
        jump_label = state->scoped_name();
      }
    }
  }
  for (auto ii = free_instructions_.rbegin(); ii != free_instructions_.rend(); ++ii)
    for (auto jj = ii->rbegin(); jj != ii->rend(); ++jj)
      emitln("%s;", jj->c_str());
  emit("goto %s", jump_label.c_str());
}

void CodegenC::emit_table_lookup(MethodCallExprNode* n) {
  TableDeclStmtNode* table = scopes_->top_table()->lookup(n->id_->name_);
  IdentExprNode* arg0 = static_cast<IdentExprNode*>(n->args_.at(0).get());
  stringstream free_inst;
  IdentExprNode* arg1;
  StructVariableDeclStmtNode* arg1_type;

  emitln("{ if (unlikely(pkt->capture)) {");
  emitln("    bpf_capture(pkt, BPF_CAP_TABLE_LOOKUP, TABLE_ID_%s, 0);", n->id_->c_str());
  emitln("} }");
  emit("%s* %s_key = &", table->key_id()->c_str(), n->id_->c_str());
  arg0->accept(this);
  emitln(";");
  emitln("%s *%s_element = (%s*)",
         table->leaf_id()->c_str(), n->id_->c_str(), table->leaf_id()->c_str());
  if (table->type_id()->name_ == "FIXED_MATCH" || table->type_id()->name_ == "INDEXED" ||
      table->type_id()->name_ == "LPM") {
    emit("  bpf_table_lookup(pkt, TABLE_ID_%s, %s_key)", n->id_->c_str(), n->id_->c_str());
    if (n->args_.size() == 2) {
      arg1 = static_cast<IdentExprNode*>(n->args_.at(1).get());
      arg1_type = static_cast<StructVariableDeclStmtNode*>(arg1->decl_);
      if (table->leaf_id()->name_ != arg1_type->struct_id_->name_) {
        throw CompilerException("lookup pointer type mismatch %s != %s", table->leaf_id()->c_str(),
                                 arg1_type->struct_id_->c_str());
      }
      emitln(";");
      // cheat a little not using arg1->accept(this) to prevent the dereference
      emit("%s%s = %s_element", arg1_type->scope_id(), arg1_type->id_->c_str(), n->id_->c_str());
    }
  } else {
    throw CompilerException("lookup in table type %s unsupported", table->type_id()->c_str());
  }
  free_instructions_.back().push_back(free_inst.str());
}

void CodegenC::emit_table_update(MethodCallExprNode* n) {
  TableDeclStmtNode* table = scopes_->top_table()->lookup(n->id_->name_);
  IdentExprNode* arg0 = static_cast<IdentExprNode*>(n->args_.at(0).get());
  IdentExprNode* arg1 = static_cast<IdentExprNode*>(n->args_.at(1).get());
  IdentExprNode* type0 = table->templates_.at(0).get();

  emit("%s* %s_ukey = &", type0->c_str(), n->id_->c_str());
  arg0->accept(this);
  emitln(";");
  if (table->type_id()->name_ == "FIXED_MATCH" || table->type_id()->name_ == "INDEXED") {
    emit("bpf_table_update(pkt, TABLE_ID_%s, %s_ukey", n->id_->c_str(), n->id_->c_str());
    emit(", &");
    arg1->accept(this);
    emitln(");");
  } else if (table->type_id()->name_ == "LPM") {
  }
}

void CodegenC::emit_table_delete(MethodCallExprNode* n) {
  TableDeclStmtNode* table = scopes_->top_table()->lookup(n->id_->name_);
  IdentExprNode* arg0 = static_cast<IdentExprNode*>(n->args_.at(0).get());
  IdentExprNode* type0 = table->templates_.at(0).get();

  emit("%s* %s_dkey = &", type0->c_str(), n->id_->c_str());
  arg0->accept(this);
  emitln(";");
  if (table->type_id()->name_ == "FIXED_MATCH" || table->type_id()->name_ == "INDEXED") {
    emit("bpf_table_delete(pkt, TABLE_ID_%s, %s_dkey", n->id_->c_str(), n->id_->c_str());
    emitln(");");
  } else if (table->type_id()->name_ == "LPM") {
  }
}

void CodegenC::emit_channel_push_generic(MethodCallExprNode* n) {
  /* computation of orig_length of packet:
   * orig_lenth = pkt->length - (orig_offset - pkt->offset)
   * push_header(N) does pkt->length += N; pkt->offset -= N;
   * pop_header(N) does pg_may_access(N); pkt->length -=N; pkt->offset +=N;
   *
   * therefore push_header(); pop_header(); sequence is currently broken, ticket #930
   */
  emit("bpf_channel_push_packet(pkt");
  emit(")");
}

void CodegenC::emit_channel_push(MethodCallExprNode* n) {
  IdentExprNode* arg0 = static_cast<IdentExprNode*>(n->args_.at(0).get());
  StructVariableDeclStmtNode* arg0_type = static_cast<StructVariableDeclStmtNode*>(arg0->decl_);
  emit("bpf_channel_push_struct(pkt, STRUCTID_%s, &", arg0_type->struct_id_->c_str());
  arg0->accept(this);
  emit(", sizeof(");
  arg0->accept(this);
  emit("))");
}

void CodegenC::emit_log(MethodCallExprNode* n) {
  emitln("{ if (unlikely(pkt->capture)) {");
  emit("    bpf_capture(pkt, BPF_CAP_LOG, %d, ", n->line_);
  n->args_[0]->accept(this);
  emit("); } }");
}

void CodegenC::emit_packet_forward(MethodCallExprNode* n) {
  emitln("pkt->arg1 &= ~1;");
  emit("bpf_forward(pkt, ");
  n->args_[0]->accept(this);
  emit(")");
}

void CodegenC::emit_packet_replicate(MethodCallExprNode*n) {
  emitln("pkt->arg1 &= ~1;");
  emit("bpf_replicate(pkt, ");
  n->args_[0]->accept(this);
  emit(",", n->id_->c_str());
  n->args_[1]->accept(this);
  emit(")");
}

void CodegenC::emit_packet_clone_forward(MethodCallExprNode* n) {
  emitln("pkt->arg1 &= ~1;");
  emit("bpf_clone_forward(pkt, ");
  n->args_[0]->accept(this);
  emit(")");
}

void CodegenC::emit_packet_forward_self(MethodCallExprNode* n) {
  emit("bpf_forward_self(pkt, ");
  n->args_[0]->accept(this);
  emit(")");
}

void CodegenC::emit_packet_drop(MethodCallExprNode* n) {
  emit("bpf_drop(pkt)");
}

void CodegenC::emit_packet_push_header(MethodCallExprNode* n) {
  emit("if (unlikely(bpf_push_header(pkt, ");
  n->args_[0]->accept(this);
  if (n->args_.size() == 1) {
    emit(", %zu, 0) != 0)) goto ERROR", n->args_[0]->struct_type_->bit_width_ >> 3);
  } else {
    emit(", %zu, ", n->args_[0]->struct_type_->bit_width_ >> 3);
    n->args_[1]->accept(this);
    emit(") != 0)) goto ERROR");
  }
}

void CodegenC::emit_packet_pop_header(MethodCallExprNode* n) {
  emit("if (unlikely(bpf_pop_header(pkt, ");
  if (n->args_[0]->typeof_ == ExprNode::STRUCT) {
    emit("%zu", n->args_[0]->struct_type_->bit_width_ >> 3);
  } else if (n->args_[0]->typeof_ == ExprNode::INTEGER) {
    n->args_[0]->accept(this);
  }
  emit(", 0/*todo*/) != 0)) goto ERROR");
}

void CodegenC::emit_packet_push_vlan(MethodCallExprNode* n) {
  emit("if (unlikely(bpf_push_vlan(pkt, bpf_htons(0x8100/*ETH_P_8021Q*/), ");
  n->args_[0]->accept(this);
  emit(") != 0)) goto ERROR");
}

void CodegenC::emit_packet_pop_vlan(MethodCallExprNode* n) {
  emit("if (unlikely(bpf_pop_vlan(pkt) != 0)) goto ERROR");
}

void CodegenC::emit_packet_rewrite_field(MethodCallExprNode* n) {
  n->args_[0]->accept(this);
  n->args_[1]->accept(this);
  emit(")");
}

void CodegenC::emit_atomic_add(MethodCallExprNode* n) {
  emit("__sync_fetch_and_add(&");
  n->args_[0]->accept(this);
  emit(", ");
  n->args_[1]->accept(this);
  emit(")");
}

void CodegenC::emit_cksum(MethodCallExprNode* n) {
  if (n->args_[0]->typeof_ == ExprNode::STRUCT) {
    auto v = n->args_[0]->struct_type_;
    size_t bit_width = v->bit_width_ >> 3;
    auto p = proto_scopes_->top_struct()->lookup(v->id_->name_, true);
    if (p) {
      /* should we do store_half directly? */
      if (!n->args_[0]->flags_[ExprNode::PROTO]) {
        emit("bpf_ntohs(bpf_checksum_pkt(pkt, %s, %zu))", v->id_->c_str(), bit_width);
      } else {
        emit("bpf_ntohs(bpf_checksum(");
        n->args_[0]->accept(this);
        emit(", %zu))", bit_width);
      }
    } else {
      throw CompilerException("cannot pg_cksum %d", n->args_[0]->typeof_);
    }
/**    emit("pg_cksum(");
    n->args_[0]->accept(this);
    emit(", %zu)", n->args_[0]->struct_type_->bit_width_ >> 3);**/
  } else {
    throw CompilerException("cannot pg_cksum %d", n->args_[0]->typeof_);
  }
}

void CodegenC::emit_incr_cksum_u16(MethodCallExprNode* n) {
  if (n->args_.size() == 3) {
    /* ip checksum */
    emit("bpf_ntohs(bpf_csum_replace2(bpf_htons(");
    n->args_[0]->accept(this);
    emit("), bpf_htons(");
    n->args_[1]->accept(this);
    emit("), bpf_htons(");
    n->args_[2]->accept(this);
    emit(")))");
  } else {
    /* L4 checksum */
    emit("(");
    /* part of pseudo header */
    n->args_[3]->accept(this);
    emit(" ? ");
    emit("((pkt->hw_csum == 1) ? ");
    /* CHECKSUM_PARTIAL update pseudo only */
    emit("bpf_ntohs(bpf_pseudo_csum_replace2(bpf_htons(");
    n->args_[0]->accept(this);
    emit("), bpf_htons(");
    n->args_[1]->accept(this);
    emit("), bpf_htons(");
    n->args_[2]->accept(this);
    emit(")))");
    emit(" : ");
    /* CHECKSUM_NONE update normally */
    emit("bpf_ntohs(bpf_csum_replace2(bpf_htons(");
    n->args_[0]->accept(this);
    emit("), bpf_htons(");
    n->args_[1]->accept(this);
    emit("), bpf_htons(");
    n->args_[2]->accept(this);
    emit(")))");
    emit(")");
    emit(" : ");
    /* not part of pseudo */
    emit("((pkt->hw_csum != 1) ? ");
    /* CHECKSUM_NONE update normally */
    emit("bpf_ntohs(bpf_csum_replace2(bpf_htons(");
    n->args_[0]->accept(this);
    emit("), bpf_htons(");
    n->args_[1]->accept(this);
    emit("), bpf_htons(");
    n->args_[2]->accept(this);
    emit(")))");
    emit(" : ");
    /* CHECKSUM_PARTIAL no-op */
    n->args_[0]->accept(this);
    emit("))");
  }
}

void CodegenC::emit_incr_cksum_u32(MethodCallExprNode* n) {
  if (n->args_.size() == 3) {
    /* ip checksum */
    emit("bpf_ntohs(bpf_csum_replace4(bpf_htons(");
    n->args_[0]->accept(this);
    emit("), bpf_htonl(");
    n->args_[1]->accept(this);
    emit("), bpf_htonl(");
    n->args_[2]->accept(this);
    emit(")))");
  } else {
    /* L4 checksum */
    emit("(");
    /* part of pseudo header */
    n->args_[3]->accept(this);
    emit(" ? ");
    emit("((pkt->hw_csum == 1) ? ");
    /* CHECKSUM_PARTIAL update pseudo only */
    emit("bpf_ntohs(bpf_pseudo_csum_replace4(bpf_htons(");
    n->args_[0]->accept(this);
    emit("), bpf_htonl(");
    n->args_[1]->accept(this);
    emit("), bpf_htonl(");
    n->args_[2]->accept(this);
    emit(")))");
    emit(" : ");
    /* CHECKSUM_NONE update normally */
    emit("bpf_ntohs(bpf_csum_replace4(bpf_htons(");
    n->args_[0]->accept(this);
    emit("), bpf_htonl(");
    n->args_[1]->accept(this);
    emit("), bpf_htonl(");
    n->args_[2]->accept(this);
    emit(")))");
    emit(")");
    emit(" : ");
    /* not part of pseudo */
    emit("((pkt->hw_csum != 1) ? ");
    /* CHECKSUM_NONE updata normally */
    emit("bpf_ntohs(bpf_csum_replace4(bpf_htons(");
    n->args_[0]->accept(this);
    emit("), bpf_htonl(");
    n->args_[1]->accept(this);
    emit("), bpf_htonl(");
    n->args_[2]->accept(this);
    emit(")))");
    emit(" : ");
    /* CHECKSUM_PARTIAL no-op */
    n->args_[0]->accept(this);
    emit("))");
  }
}

void CodegenC::emit_lb_hash(MethodCallExprNode* n) {
  emit("pg_lb_hash(");
  n->args_[0]->accept(this);
  emit(", ");
  n->args_[1]->accept(this);
  emit(")");
}

void CodegenC::emit_sizeof(MethodCallExprNode* n) {
  if (n->args_[0]->typeof_ == ExprNode::STRUCT) {
    if (n->args_[0]->struct_type_->id_->name_ == "_Packet") {
      emit("PG_SIZEOF(pkt)");
    } else {
      emit("%zu", n->args_[0]->struct_type_->bit_width_ >> 3);
    }
  } else if (n->args_[0]->typeof_ == ExprNode::INTEGER) {
    emit("%zu", n->args_[0]->bit_width_ >> 3);
  }
}

void CodegenC::emit_get_usec_time(MethodCallExprNode* n) {
  emit("bpf_get_usec_time()");
}

void CodegenC::emit_forward_to_vnf(MethodCallExprNode*n) {
  emitln("pkt->arg1 |= 1;");
  emit("pkt->arg2 = ");
  n->args_[0]->accept(this);
  emitln(";");
  emit("bpf_forward_to_plum(pkt, ");
  n->args_[1]->accept(this);
  emit(")");

}

void CodegenC::emit_forward_to_group(MethodCallExprNode *n) {

  emit("pkt->arg2 = ");
  n->args_[0]->accept(this);
  emitln(";");
  emitln("pkt->arg3 = pkt->plum_id;");
  emit("bpf_forward_to_plum(pkt, ");
  emit("1/*TUNNEL_PLUM_ID*/");
  emit(")");

}

void CodegenC::visit_method_call_expr_node(MethodCallExprNode* n) {
  free_instructions_.push_back(vector<string>());

  if (!n->stmts_.empty()) {
    ++indent_;
    emitln("{");
  }

  if (n->id_->sub_name_.size()) {
    if (n->id_->sub_name_ == "lookup") {
      emit_table_lookup(n);
    } else if (n->id_->sub_name_ == "update") {
      emit_table_update(n);
    } else if (n->id_->sub_name_ == "delete") {
      emit_table_delete(n);
    } else if (n->id_->sub_name_ == "replicate" && n->id_->name_ == "pkt") {
      emit_packet_replicate(n);
    } else if (n->id_->sub_name_ == "forward" && n->id_->name_ == "pkt") {
      emit_packet_forward(n);
    } else if (n->id_->sub_name_ == "forward_self" && n->id_->name_ == "pkt") {
      emit_packet_forward_self(n);
    } else if (n->id_->sub_name_ == "push_header" && n->id_->name_ == "pkt") {
      emit_packet_push_header(n);
    } else if (n->id_->sub_name_ == "pop_header" && n->id_->name_ == "pkt") {
      emit_packet_pop_header(n);
    } else if (n->id_->sub_name_ == "push_vlan" && n->id_->name_ == "pkt") {
      emit_packet_push_vlan(n);
    } else if (n->id_->sub_name_ == "pop_vlan" && n->id_->name_ == "pkt") {
      emit_packet_pop_vlan(n);
    } else if (n->id_->sub_name_ == "rewrite_field" && n->id_->name_ == "pkt") {
      emit_packet_rewrite_field(n);
    } else if (n->id_->sub_name_ == "clone_forward" && n->id_->name_ == "pkt") {
      emit_packet_clone_forward(n);
    }
  } else if (n->id_->name_ == "atomic_add") {
    emit_atomic_add(n);
  } else if (n->id_->name_ == "log") {
    emit_log(n);
  } else if (n->id_->name_ == "cksum") {
    emit_cksum(n);
  } else if (n->id_->name_ == "incr_cksum_u16") {
    emit_incr_cksum_u16(n);
  } else if (n->id_->name_ == "incr_cksum_u32") {
    emit_incr_cksum_u32(n);
  } else if (n->id_->name_ == "lb_hash") {
    emit_lb_hash(n);
  } else if (n->id_->name_ == "sizeof") {
    emit_sizeof(n);
  } else if (n->id_->name_ == "get_usec_time") {
    emit_get_usec_time(n);
  } else if (n->id_->name_ == "channel_push") {
    emit_channel_push(n);
  } else if (n->id_->name_ == "channel_push_generic") {
    emit_channel_push_generic(n);
  } else if (n->id_->name_ == "forward_to_vnf") {
    emit_forward_to_vnf(n);
  } else if (n->id_->name_ == "forward_to_group") {
    emit_forward_to_group(n);
  } else {
    n->id_->accept(this);
    emit("(");
    for (auto it = n->args_.begin(); it != n->args_.end(); ++it) {
      (*it)->accept(this);
      if (it + 1 != n->args_.end()) {
        emit(", ");
      }
    }
    emit(")");
  }
  if (!n->stmts_.empty()) {
    emit(";");
    for (auto it = n->stmts_.begin(); it != n->stmts_.end(); ++it) {
      lnemit("");
      (*it)->accept(this);
    }
    for (auto it = free_instructions_.back().rbegin(); it != free_instructions_.back().rend(); ++it) {
      lnemit("%s;", it->c_str());
    }
    --indent_;
    lnemit("}");
  }
  free_instructions_.pop_back();
}

/// on_match
void CodegenC::visit_match_decl_stmt_node(MatchDeclStmtNode* n) {
  if (n->formals_.size() != 2)
    throw CompilerException("on_match expected 2 arguments, %zu given", n->formals_.size());
  StructVariableDeclStmtNode* key_n = static_cast<StructVariableDeclStmtNode*>(n->formals_.at(0).get());
  StructVariableDeclStmtNode* leaf_n = static_cast<StructVariableDeclStmtNode*>(n->formals_.at(1).get());
  if (!key_n || !leaf_n)
    throw CompilerException("invalid parameter type");
  ++indent_;
  emitln("if (%s_element) {", n->id_->c_str());
  emitln("%s* %s%s = %s_key;", key_n->struct_id_->c_str(), key_n->scope_id(),
         key_n->id_->c_str(), n->id_->c_str());
  emitln("%s* %s%s = %s_element;", leaf_n->struct_id_->c_str(), leaf_n->scope_id(),
         leaf_n->id_->c_str(), n->id_->c_str());
  n->block_->accept(this);
  --indent_;
  emitln("");
  emit("}");
}

/// on_miss
void CodegenC::visit_miss_decl_stmt_node(MissDeclStmtNode* n) {
  if (n->formals_.size() != 1)
    throw CompilerException("on_match expected 1 argument, %zu given", n->formals_.size());
  StructVariableDeclStmtNode* key_n = static_cast<StructVariableDeclStmtNode*>(n->formals_.at(0).get());
  ++indent_;
  emitln("if (!%s_element) {", n->id_->c_str());
  emitln("%s* %s%s = %s_key;", key_n->struct_id_->c_str(),
         key_n->scope_id(), key_n->id_->c_str(), n->id_->c_str());
  n->block_->accept(this);
  --indent_;
  emitln("");
  emit("}");
}

void CodegenC::visit_failure_decl_stmt_node(FailureDeclStmtNode* n) {
  if (n->formals_.size() != 1)
    throw CompilerException("on_failure expected 1 argument, %zu given", n->formals_.size());
  StructVariableDeclStmtNode* key_n = static_cast<StructVariableDeclStmtNode*>(n->formals_.at(0).get());
  ++indent_;
  emitln("/*if ((unsigned long)%s_element >= (unsigned long)-4095) {", n->id_->name_.c_str());
  emitln("%s* %s%s = %s_key;", key_n->struct_id_->c_str(),
         key_n->scope_id(), key_n->id_->c_str(), n->id_->c_str());
  n->block_->accept(this);
  --indent_;
  emitln("");
  emit("}*/");
}

void CodegenC::visit_expr_stmt_node(ExprStmtNode* n) {
  emit_comment(n);
  n->expr_->accept(this);
  emit(";");
}

void CodegenC::visit_struct_variable_decl_stmt_node(StructVariableDeclStmtNode* n) {
  if (n->struct_id_->name_ == "" || n->struct_id_->name_[0] == '_') {
    return;
  }
  emit_comment(n);
  if (n->struct_id_->scope_name_ == "proto") {
    auto p = proto_scopes_->top_struct()->lookup(n->struct_id_->name_, true);
    if (p) {
      string var = n->scope_id() + n->id_->name_;
      /* zero initialize array to be filled in with packet header */
      emit("uint64_t __%s[%zu] = {}; uint8_t *%s = (uint8_t*)__%s;",
           var.c_str(), ((p->bit_width_ >> 3) + 7) >> 3, var.c_str(), var.c_str());
      for (auto it = n->init_.begin(); it != n->init_.end(); ++it) {
        auto asn = static_cast<AssignExprNode*>(it->get());
        if (auto f = p->field(asn->id_->sub_name_)) {
          size_t bit_offset = f->bit_offset_;
          size_t bit_width = f->bit_width_;
          if (asn->bitop_) {
            bit_offset += f->bit_width_ - (asn->bitop_->bit_offset_ + asn->bitop_->bit_width_);
            bit_width = std::min(bit_width - asn->bitop_->bit_offset_, asn->bitop_->bit_width_);
          }
          emit(" bpf_dins(%s + %zu, %zu, %zu, ", var.c_str(), bit_offset >> 3, bit_offset & 0x7, bit_width);
          asn->rhs_->accept(this);
          emit(");");
        }
      }
    }
  } else {
    /* all structs must be initialized with zeros, since they're alocated on stack,
     * if struct doesn't have gaps between fields, gcc will be smart enough to avoid redundant zeroing */
    if (n->storage_type_ == VariableDeclStmtNode::STRUCT_REFERENCE) {
      emit("%s* %s%s = 0;", n->struct_id_->c_str(), n->scope_id(), n->id_->c_str());
    } else {
      emit("%s %s%s = {};", n->struct_id_->c_str(), n->scope_id(), n->id_->c_str());
      if (!n->init_.empty()) {
        for (auto it = n->init_.begin(); it != n->init_.end(); ++it) {
          emit(" ");
          (*it)->accept(this);
          emit(";");
        }
      }
    }
  }
}

void CodegenC::visit_integer_variable_decl_stmt_node(IntegerVariableDeclStmtNode* n) {
  if (n->id_->name_ == "timer_delay" || n->id_->name_ == "parsed_bytes")
    return;
  emit_comment(n);
  emit("%s %s%s", bits_to_uint(n->bit_width_), n->scope_id(), n->id_->c_str());
  if (!n->scope_id_.empty())
    emit(" = 0");
  if (!n->init_.empty()) {
    emit("; ");
    n->init_[0]->accept(this);
  }
  emit(";");
}

void CodegenC::visit_struct_decl_stmt_node(StructDeclStmtNode* n) {
  emit("typedef struct {\n");
  ++indent_;
  for (auto it = n->stmts_.begin(); it != n->stmts_.end(); ++it) {
    indent();
    (*it)->accept(this);
    emit("\n");
  }
  --indent_;
  indent();
  emit("} __attribute__((aligned(4))) ");
  emit("%s", n->id_->c_str());
}

void CodegenC::visit_parser_state_stmt_node(ParserStateStmtNode* n) {
  string jump_label = n->scoped_name() + "_continue";
  emit("%s: {", jump_label.c_str());
  ++indent_;
  lnemit("PG_TRACE(%.14s);", jump_label.c_str());
  if (n->next_state_) {
    lnemit("");
    n->next_state_->accept(this);
  }
  --indent_;
  lnemit("}");
}

void CodegenC::visit_timer_decl_stmt_node(TimerDeclStmtNode* n) {
  auto scope = scopes_->current_state();
  scopes_->set_current(n->scope_);
  n->block_->accept(this);
  scopes_->set_current(scope);
}
void CodegenC::visit_state_decl_stmt_node(StateDeclStmtNode* n) {
  if (!n->id_) {
    return;
  }
  string jump_label = n->scoped_name();
  ++indent_;
  emitln("JUMP_GUARD; %s: {", jump_label.c_str());
  emitln("PG_TRACE(%.14s);", jump_label.c_str());
  if (auto p = proto_scopes_->top_struct()->lookup(n->id_->name_, true)) {
    emitln("%s = parsed_bytes; /* remember the offset of this header */", n->id_->c_str());
    emitln("parsed_bytes += %zu;", p->bit_width_ >> 3);
    //emitln("if (!pg_may_access(pkt, parsed_bytes)) goto ERROR; /* pull data from fragments to access this header */");
  }
  // collect the protocols used in this state scope and declare them
  set<string> protos;
  for (auto it = n->subs_.begin(); it != n->subs_.end(); ++it) {
    if (!it->scope_) {
      continue;
    }
    auto scope = scopes_->current_state();
    scopes_->set_current(it->scope_);
    for (auto it2 = scopes_->current_state()->obegin(); it2 != scopes_->current_state()->oend(); ++it2) {
      if (proto_scopes_->top_struct()->lookup((*it2)->id_->name_, true)) {
        protos.insert((*it2)->id_->name_);
      }
      for (auto it3 = (*it2)->subs_.begin(); it3 != (*it2)->subs_.end(); ++it3) {
        if (proto_scopes_->top_struct()->lookup(it3->id_->name_, true)) {
          protos.insert(it3->id_->name_);
        }
      }
    }
    scopes_->set_current(scope);
  }
  for (auto it = protos.begin(); it != protos.end(); ++it) {
    emitln("uint32_t %s = 0; /* header offset */", it->c_str());
  }

  auto it = n->subs_.begin();
  if (n->subs_.size() == 1 && it->id_->name_ == "") {
    // this is not a multistate protocol, emit everything and finish
    auto scope = scopes_->current_state();
    scopes_->set_current(it->scope_);
    it->block_->accept(this);
    if (n->parser_) {
      emitln("");
      n->parser_->accept(this);
    }
    scopes_->set_current(scope);
  } else {
    if (n->parser_) {
      for (auto it2 = n->subs_.begin(); it2 != n->subs_.end(); ++it2) {
        proto_rewrites_[it2->id_->full_name()] = n->scoped_name() + "_" + it2->id_->name_;
      }
      n->parser_->accept(this);
      proto_rewrites_.clear();
      emitln("");
    }
    for (; it != n->subs_.end(); ++it) {
      auto scope = scopes_->current_state();
      scopes_->set_current(it->scope_);

      string jump_label = n->scoped_name() + "_" + it->id_->name_;
      ++indent_;
      emitln("JUMP_GUARD; %s: {", jump_label.c_str());
      emitln("PG_TRACE(%.14s);", jump_label.c_str());
      if (auto p = proto_scopes_->top_struct()->lookup(it->id_->name_, true)) {
        emitln("%s = pkt->offset + parsed_bytes; /* remember the offset of this header */", it->id_->c_str());
        emitln("parsed_bytes += %zu;", p->bit_width_ >> 3);
        emitln("if (!pg_may_access(pkt, parsed_bytes)) goto ERROR; /* pull data from fragments to access this header */");
      }
      it->block_->accept(this);
      if (it->parser_) {
        emitln("");
        it->parser_->accept(this);
      }
      --indent_;
      emitln("");
      emitln("}");

      scopes_->set_current(scope);
    }
  }

  --indent_;
  emitln("");
  emit("}");
}

void CodegenC::visit_table_decl_stmt_node(TableDeclStmtNode* n) {
  if (n->table_type_->name_ == "Table"
      || n->table_type_->name_ == "SharedTable") {
    if (n->templates_.size() != 4)
      throw CompilerException("%s expected 4 arguments, %zu given", n->table_type_->c_str(), n->templates_.size());
    const char *key_type = n->key_id()->c_str();
    const char *leaf_type = n->leaf_id()->c_str();
    char buf[128];
    if (n->type_id()->name_ == "FIXED_MATCH" || n->type_id()->name_ == "INDEXED") {
      //emitln("struct %s_Element {", n->id_->c_str());
      //emitln("  PG_HASH_TABLE_ELEMENT_COMMON");
      //emitln("  %s key;", key_type);
      //emitln("  %s leaf;", leaf_type);
      //emitln("} __attribute__((aligned(8)));");
      //emitln("static struct PGHashTable %s;", n->id_->c_str());
      //emitln("#define N_BUCKETS_%s %zu", n->id_->c_str(), n->size_);
      //emitln("PG_HASH_TABLE_DECL(%d, %s, sizeof(%s), sizeof(struct %s_Element), N_BUCKETS_%s)",
      //       table_inits_.size(), n->id_->c_str(), key_type, n->id_->c_str(), n->id_->c_str());
      emitln("#define TABLE_ID_%s %zd", n->id_->c_str(), table_inits_.size());
      snprintf(buf, sizeof(buf), "[%zd] = {%zd, PG_TABLE_HASH, sizeof(%s), sizeof(%s), %zd, 0}, // %s",
               table_inits_.size(), table_inits_.size(), key_type, leaf_type, n->size_, n->id_->c_str());
    } else if (n->type_id()->name_ == "LPM") {
      //emitln("struct %s_Element {", n->id_->c_str());
      //emitln("  PG_LPM_TABLE_ELEMENT_COMMON");
      //emitln("  %s key;", key_type);
      //emitln("  %s leaf;", leaf_type);
      //emitln("} __attribute__((aligned(8)));");
      //emitln("static struct PGLpmTable %s;", n->id_->c_str());
      //emitln("#define N_BUCKETS_%s %zu", n->id_->c_str(), n->size_);
      //emitln("PG_LPM_TABLE_DECL(%d, %s, sizeof(%s), sizeof(struct %s_Element), N_BUCKETS_%s, %u)",
      //       table_inits_.size(), n->id_->c_str(), key_type, n->id_->c_str(), n->id_->c_str(),
      //       n->key_id()->bit_width_);
      emitln("#define TABLE_ID_%s %zd", n->id_->c_str(), table_inits_.size());
      snprintf(buf, sizeof(buf), "[%zd] = {%zd, PG_TABLE_LPM, sizeof(%s), sizeof(%s), %zd, %zd}, // %s",
               table_inits_.size(), table_inits_.size(), key_type, leaf_type, n->size_,
               n->key_id()->bit_width_, n->id_->c_str());
    } else {
      throw CompilerException("table type \"%s\" unknown", n->type_id()->c_str());
    }
    //table_inits_.push_back(n->id_->name_);
    table_inits_.push_back(buf);
  }
}

int CodegenC::visit(Node* root) {
  BlockStmtNode* b = static_cast<BlockStmtNode*>(root);


  scopes_->set_current(scopes_->top_state());
  scopes_->set_current(scopes_->top_var());

  print_header();

  b->ver_.accept(this);

  for (auto it = scopes_->top_table()->obegin(); it != scopes_->top_table()->oend(); ++it) {
    (*it)->accept(this);
    emit("\n");
  }

  print_parser();

  print_footer();

  return 0;
}

void CodegenC::print_timer() {
  // visit timers
  ++indent_;
  emitln("PG_PARSE_DECL(timer) {");
  emitln("uint32_t timer_delay = 0;");
  // visit function scoped variables
  for (auto it = scopes_->current_var()->obegin(); it != scopes_->current_var()->oend(); ++it) {
    (*it)->accept(this);
    emitln("");
  }
  for (auto it = scopes_->top_timer()->obegin(); it != scopes_->top_timer()->oend(); ++it) {
    (*it)->accept(this);
    emitln("");
  }
  ++indent_;
  emitln("DONE: {");
  emitln("PG_TRACE(DONE);");
  emitln("pg_timer_forward(pkt, timer_delay);");
  --indent_;
  emitln("return;");
  emitln("}");

  ++indent_;
  emitln("ERROR: {");
  emitln("PG_TRACE(ERROR);");
  emitln("pg_drop(pkt);");
  emitln("pg_timer_forward(pkt, timer_delay);");
  --indent_;
  emitln("return;");
  --indent_;
  emitln("}");
  emitln("}");
}

void CodegenC::print_parser() {
  ++indent_;
  emitln("PG_PARSE_DECL(parse) {");
  /* emitln("uint8_t *pp;"); */
  emitln("uint32_t parsed_bytes = 0;");
  emitln("uint16_t orig_offset = 0;/*pkt->offset;*/");

  // visit function scoped variables
  for (auto it = scopes_->current_var()->obegin(); it != scopes_->current_var()->oend(); ++it) {
    (*it)->accept(this);
    emitln("");
  }

  for (auto it = scopes_->current_state()->obegin(); it != scopes_->current_state()->oend(); ++it) {
    if (proto_scopes_->top_struct()->lookup((*it)->id_->name_, true)) {
      emitln("uint32_t %s = 0; /* header offset */", (*it)->id_->c_str());
    }
  }

  /* emitln("pp = pkt->start + pkt->offset;"); */
  emitln("goto s1_INIT;");

  // finally, visit the states
  for (auto it = scopes_->current_state()->obegin(); it != scopes_->current_state()->oend(); ++it) {
    (*it)->accept(this);
    emitln("");
  }

  ++indent_;
  emitln("ERROR: {");
  emitln("PG_TRACE(ERROR);");
  --indent_;
  emitln("goto CLEANUP;");
  emitln("}");

  ++indent_;
  emitln("DONE: {");
  emitln("PG_TRACE(DONE);");
  --indent_;
  emitln("goto CLEANUP;");
  emitln("}");

  ++indent_;
  emitln("CLEANUP: {");
  --indent_;
  emitln("/* cleanup is done by PE */;");
  --indent_;
  emitln("}");

  emitln("}");

  //print_timer();
}

void CodegenC::print_header() {
  if (use_pre_header_) {
    //emit("%s", PRE_HEADER.c_str());
    emitln("");
  } else {
    emitln("#include <stdint.h>");
    emitln("#include \"../dp/linux/filter.h\"");
    emitln("#include \"container/pg_api.h\"");
    emitln("#include \"container/pg_defs.h\"");
  }
  emitln("#define JUMP_GUARD goto DONE");
  emitln("#define PG_SIZEOF(_pkt) ((int)_pkt->length - (int)pkt->offset + orig_offset)");

  int i = 0;
  // declare structures
  for (auto it = scopes_->top_struct()->obegin(); it != scopes_->top_struct()->oend(); ++it) {
    if ((*it)->id_->name_ == "_Packet")
      continue;
    (*it)->accept(this);
    emit(";\n");
    emitln("#define STRUCTID_%s %d", (*it)->id_->c_str(), i++);
  }
  emitln("#define STRUCTID_generic %d", i);
}

void CodegenC::print_footer() {
  //emitln("#define EXPAND_TABLES(E) \\");
  emitln("struct bpf_table plum_tables[] = {");
  for (auto it = table_inits_.begin(); it != table_inits_.end(); ++it) {
    //emit("E(%s) ", it->c_str());
    emitln("  %s", it->c_str());
  }
  emitln("  {0,0,0,0,0,0} // last table marker");
  emitln("};");
  emitln("");
  emitln("PG_INIT");
  emitln("PG_CLEANUP");
}

}  // namespace cc
}  // namespace ebpf
