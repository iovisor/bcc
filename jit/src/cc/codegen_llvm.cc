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

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/CallingConv.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRPrintingPasses.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include "exception.h"
#include "cc/codegen_llvm.h"
#include "cc/lexer.h"
#include "cc/type_helper.h"
#include "linux/bpf.h"

extern "C"
int bpf_create_map(int map_type, int key_size, int value_size, int max_entries);

#define ENABLE_RELOCATIONS 0

namespace ebpf {
namespace cc {

using namespace llvm;

using std::for_each;
using std::make_tuple;
using std::pair;
using std::set;
using std::string;
using std::stringstream;
using std::to_string;
using std::vector;

// can't forward declare IRBuilder in .h file (template with default
// parameters), so cast it instead :(
#define B (*((IRBuilder<> *)this->b_))

class BlockStack {
 public:
  explicit BlockStack(CodegenLLVM *cc, BasicBlock *bb)
    : old_bb_(cc->b_->GetInsertBlock()), cc_(cc) {
    cc_->b_->SetInsertPoint(bb);
  }
  ~BlockStack() {
    if (old_bb_)
      cc_->b_->SetInsertPoint(old_bb_);
    else
      cc_->b_->ClearInsertionPoint();
  }
 private:
  BasicBlock *old_bb_;
  CodegenLLVM *cc_;
};

class SwitchStack {
 public:
  explicit SwitchStack(CodegenLLVM *cc, SwitchInst *sw)
    : old_sw_(cc->cur_switch_), cc_(cc) {
    cc_->cur_switch_ = sw;
  }
  ~SwitchStack() {
    cc_->cur_switch_ = old_sw_;
  }
 private:
  SwitchInst *old_sw_;
  CodegenLLVM *cc_;
};

CodegenLLVM::CodegenLLVM(llvm::Module *mod, Scopes *scopes, Scopes *proto_scopes,
                         bool use_pre_header, const string &section)
  : out_(stdout), mod_(mod), indent_(0), tmp_reg_index_(0), scopes_(scopes),
    proto_scopes_(proto_scopes), use_pre_header_(use_pre_header),
    section_(section), expr_(nullptr) {
  b_ = new IRBuilder<>(ctx());
}
CodegenLLVM::~CodegenLLVM() {
  delete b_;
}

template <typename... Args>
void CodegenLLVM::emitln(const char *fmt, Args&&... params) {
  //fprintf(out_, fmt, std::forward<Args>(params)...);
  //fprintf(out_, "\n%*s", indent_ * 2, "");
  //fflush(out_);
}
void CodegenLLVM::emitln(const char *s) {
  //fprintf(out_, "%s", s);
  //fprintf(out_, "\n%*s", indent_ * 2, "");
  //fflush(out_);
}

template <typename... Args>
void CodegenLLVM::emit(const char *fmt, Args&&... params) {
  //fprintf(out_, fmt, std::forward<Args>(params)...);
  //fflush(out_);
}
void CodegenLLVM::emit(const char *s) {
  //fprintf(out_, "%s", s);
  //fflush(out_);
}

template <typename... Args>
void CodegenLLVM::lnemit(const char *fmt, Args&&... params) {
  //fprintf(out_, "\n%*s", indent_ * 2, "");
  //fprintf(out_, fmt, std::forward<Args>(params)...);
  //fflush(out_);
}
void CodegenLLVM::lnemit(const char *s) {
  //fprintf(out_, "\n%*s", indent_ * 2, "");
  //fprintf(out_, "%s", s);
  //fflush(out_);
}

void CodegenLLVM::indent() {
  //fprintf(out_, "%*s", indent_ * 2, "");
  //fflush(out_);
}

void CodegenLLVM::emit_comment(Node *n) {
  // if (!n->text_.empty()) {
  //   emitln("/* %s */", n->text_.c_str());
  // }
}

StatusTuple CodegenLLVM::visit_block_stmt_node(BlockStmtNode *n) {

  // enter scope
  auto scope = scopes_->current_var();
  if (n->scope_) {
    scopes_->set_current(n->scope_);
  }

  if (!n->stmts_.empty()) {
    for (auto it = n->stmts_.begin(); it != n->stmts_.end(); ++it)
      TRY2((*it)->accept(this));
  }
  // exit scope
  scopes_->set_current(scope);

  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_version_stmt_node(VersionStmtNode *n) {
  uint32_t version;
  version = MAKE_VERSION(n->major_, n->minor_, n->rev_);
  emit("static const uint32_t  plumlet_version   __attribute__"
      "((section (\".version\"), used)) = 0x%x;\n", version);
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_if_stmt_node(IfStmtNode *n) {
  Function *parent = B.GetInsertBlock()->getParent();
  BasicBlock *label_then = BasicBlock::Create(ctx(), "if.then", parent);
  BasicBlock *label_else = n->false_block_ ? BasicBlock::Create(ctx(), "if.else", parent) : nullptr;
  BasicBlock *label_end = BasicBlock::Create(ctx(), "if.end", parent);

  TRY2(n->cond_->accept(this));

  if (n->false_block_)
    B.CreateCondBr(pop_expr(), label_then, label_else);
  else
    B.CreateCondBr(pop_expr(), label_then, label_end);

  {
    BlockStack bstack(this, label_then);
    TRY2(n->true_block_->accept(this));
    if (!B.GetInsertBlock()->getTerminator())
      B.CreateBr(label_end);
  }

  if (n->false_block_) {
    BlockStack bstack(this, label_else);
    TRY2(n->false_block_->accept(this));
    if (!B.GetInsertBlock()->getTerminator())
      B.CreateBr(label_end);
  }

  B.SetInsertPoint(label_end);

  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_onvalid_stmt_node(OnValidStmtNode *n) {
  TRY2(n->cond_->accept(this));

  Value *is_null = B.CreateIsNotNull(pop_expr());

  Function *parent = B.GetInsertBlock()->getParent();
  BasicBlock *label_then = BasicBlock::Create(ctx(), "onvalid.then", parent);
  BasicBlock *label_else = n->else_block_ ? BasicBlock::Create(ctx(), "onvalid.else", parent) : nullptr;
  BasicBlock *label_end = BasicBlock::Create(ctx(), "onvalid.end", parent);

  if (n->else_block_)
    B.CreateCondBr(is_null, label_then, label_else);
  else
    B.CreateCondBr(is_null, label_then, label_end);

  {
    BlockStack bstack(this, label_then);
    TRY2(n->block_->accept(this));
    if (!B.GetInsertBlock()->getTerminator())
      B.CreateBr(label_end);
  }

  if (n->else_block_) {
    BlockStack bstack(this, label_else);
    TRY2(n->else_block_->accept(this));
    if (!B.GetInsertBlock()->getTerminator())
      B.CreateBr(label_end);
  }

  B.SetInsertPoint(label_end);
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_switch_stmt_node(SwitchStmtNode *n) {
  Function *parent = B.GetInsertBlock()->getParent();
  BasicBlock *label_default = BasicBlock::Create(ctx(), "switch.default", parent);
  BasicBlock *label_end = BasicBlock::Create(ctx(), "switch.end", parent);
  // switch (cond)
  TRY2(n->cond_->accept(this));
  SwitchInst *switch_inst = B.CreateSwitch(pop_expr(), label_default);
  B.SetInsertPoint(label_end);
  {
    // case 1..N
    SwitchStack sstack(this, switch_inst);
    TRY2(n->block_->accept(this));
  }
  // if other cases are terminal, erase the end label
  if (pred_empty(label_end))
    label_end->eraseFromParent();
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_case_stmt_node(CaseStmtNode *n) {
  if (!cur_switch_) return mkstatus_(n, "no valid switch instruction");
  Function *parent = B.GetInsertBlock()->getParent();
  BasicBlock *label_end = B.GetInsertBlock();
  BasicBlock *dest;
  if (n->value_) {
    TRY2(n->value_->accept(this));
    dest = BasicBlock::Create(ctx(), "switch.case", parent);
    Value *cond = B.CreateIntCast(pop_expr(), cur_switch_->getCondition()->getType(), false);
    cur_switch_->addCase(cast<ConstantInt>(cond), dest);
  } else {
    dest = cur_switch_->getDefaultDest();
  }
  {
    BlockStack bstack(this, dest);
    TRY2(n->block_->accept(this));
    // if no trailing goto, fall to end
    if (!B.GetInsertBlock()->getTerminator())
      B.CreateBr(label_end);
  }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_ident_expr_node(IdentExprNode *n) {
  if (!n->decl_)
    return mkstatus_(n, "variable lookup failed: %s", n->name_.c_str());
  if (n->decl_->is_pointer()) {
    if (n->sub_name_.size()) {
      if (n->bitop_) {
        // ident is holding a host endian number, don't use dext
        if (n->is_lhs()) {
          emit("%s%s->%s", n->decl_->scope_id(), n->c_str(), n->sub_name_.c_str());
        } else {
          emit("(((%s%s->%s) >> %d) & (((%s)1 << %d) - 1))", n->decl_->scope_id(), n->c_str(), n->sub_name_.c_str(),
              n->bitop_->bit_offset_, bits_to_uint(n->bitop_->bit_width_ + 1), n->bitop_->bit_width_);
        }
        return mkstatus_(n, "unsupported");
      } else {
        if (n->struct_type_->id_->name_ == "_Packet" && n->sub_name_.substr(0, 3) == "arg") {
          // convert arg1~arg8 into args[0]~args[7] assuming type_check verified the range already
          auto arg_num = stoi(n->sub_name_.substr(3, 3));
          if (arg_num < 5) {
            emit("%s%s->args_lo[%d]", n->decl_->scope_id(), n->c_str(), arg_num - 1);
          } else {
            emit("%s%s->args_hi[%d]", n->decl_->scope_id(), n->c_str(), arg_num - 5);
          }
          return mkstatus_(n, "unsupported");
        } else {
          emit("%s%s->%s", n->decl_->scope_id(), n->c_str(), n->sub_name_.c_str());
          auto it = vars_.find(n->decl_);
          if (it == vars_.end()) return mkstatus_(n, "Cannot locate variable %s in vars_ table", n->c_str());
          LoadInst *load_1 = B.CreateLoad(it->second);
          vector<Value *> indices({B.getInt32(0), B.getInt32(n->sub_decl_->slot_)});
          expr_ = B.CreateInBoundsGEP(load_1, indices);
          if (!n->is_lhs())
            expr_ = B.CreateLoad(pop_expr());
        }
      }
    } else {
      emit("*%s%s", n->decl_->scope_id(), n->c_str());
      auto it = vars_.find(n->decl_);
      if (it == vars_.end()) return mkstatus_(n, "Cannot locate variable %s in vars_ table", n->c_str());
      LoadInst *load_1 = B.CreateAlignedLoad(it->second, 4);
      expr_ = load_1;
    }
  } else {
    if (n->sub_name_.size()) {
      emit("%s%s.%s", n->decl_->scope_id(), n->c_str(), n->sub_name_.c_str());
      auto it = vars_.find(n->decl_);
      if (it == vars_.end()) return mkstatus_(n, "Cannot locate variable %s in vars_ table", n->c_str());
      vector<Value *> indices({const_int(0), const_int(n->sub_decl_->slot_, 32)});
      expr_ = B.CreateGEP(nullptr, it->second, indices);
      if (!n->is_lhs())
        expr_ = B.CreateLoad(pop_expr());
    } else {
      if (n->bitop_) {
        // ident is holding a host endian number, don't use dext
        if (n->is_lhs())
          return mkstatus_(n, "illegal: ident %s is a left-hand-side type", n->name_.c_str());
        if (n->decl_->is_struct())
          return mkstatus_(n, "illegal: can only take bitop of a struct subfield");
        emit("(((%s%s) >> %d) & (((%s)1 << %d) - 1))", n->decl_->scope_id(), n->c_str(),
             n->bitop_->bit_offset_, bits_to_uint(n->bitop_->bit_width_ + 1), n->bitop_->bit_width_);
      } else {
        emit("%s%s", n->decl_->scope_id(), n->c_str());
        auto it = vars_.find(n->decl_);
        if (it == vars_.end()) return mkstatus_(n, "Cannot locate variable %s in vars_ table", n->c_str());
        if (n->is_lhs() || n->decl_->is_struct())
          expr_ = it->second;
        else
          expr_ = B.CreateLoad(it->second);
      }
    }
  }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_assign_expr_node(AssignExprNode *n) {
  if (n->bitop_) {
    TRY2(n->id_->accept(this));
    emit(" = (");
    TRY2(n->id_->accept(this));
    emit(" & ~((((%s)1 << %d) - 1) << %d)) | (", bits_to_uint(n->id_->bit_width_),
         n->bitop_->bit_width_, n->bitop_->bit_offset_);
    TRY2(n->rhs_->accept(this));
    emit(" << %d)", n->bitop_->bit_offset_);
    return mkstatus_(n, "unsupported");
  } else {
    if (n->id_->flags_[ExprNode::PROTO]) {
      auto f = n->id_->struct_type_->field(n->id_->sub_name_);
      emit("bpf_dins(%s%s + %zu, %zu, %zu, ", n->id_->decl_->scope_id(), n->id_->c_str(),
           f->bit_offset_ >> 3, f->bit_offset_ & 0x7, f->bit_width_);
      TRY2(n->rhs_->accept(this));
      emit(")");
      return mkstatus_(n, "unsupported");
    } else {
      TRY2(n->id_->accept(this));
      Value *lhs = pop_expr();
      TRY2(n->rhs_->accept(this));
      expr_ = B.CreateIntCast(expr_, cast<PointerType>(lhs->getType())->getElementType(), false);
      B.CreateStore(pop_expr(), lhs);
    }
  }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::lookup_var(Node *n, const string &name, Scopes::VarScope *scope,
                                    VariableDeclStmtNode **decl, Value **mem) const {
  *decl = scope->lookup(name, false);
  if (!*decl) return mkstatus_(n, "cannot find %s variable", name.c_str());
  auto it = vars_.find(*decl);
  if (it == vars_.end()) return mkstatus_(n, "unable to find %s memory location", name.c_str());
  *mem = it->second;
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_packet_expr_node(PacketExprNode *n) {
  auto p = proto_scopes_->top_struct()->lookup(n->id_->name_, true);
  VariableDeclStmtNode *offset_decl, *skb_decl;
  Value *offset_mem, *skb_mem;
  TRY2(lookup_var(n, "skb", scopes_->top_var(), &skb_decl, &skb_mem));
  TRY2(lookup_var(n, "$" + n->id_->name_, scopes_->current_var(), &offset_decl, &offset_mem));

  if (p) {
    auto f = p->field(n->id_->sub_name_);
    if (f) {
      size_t bit_offset = f->bit_offset_;
      size_t bit_width = f->bit_width_;
      if (n->bitop_) {
        bit_offset += f->bit_width_ - (n->bitop_->bit_offset_ + n->bitop_->bit_width_);
        bit_width = std::min(bit_width - n->bitop_->bit_offset_, n->bitop_->bit_width_);
      }
      if (n->is_ref()) {
        // e.g.: @ip.hchecksum, return offset of the header within packet
        LoadInst *offset_ptr = B.CreateLoad(offset_mem);
        Value *skb_hdr_offset = B.CreateAdd(offset_ptr, B.getInt64(bit_offset >> 3));
        expr_ = B.CreateIntCast(skb_hdr_offset, B.getInt64Ty(), false);
      } else if (n->is_lhs()) {
        emit("bpf_dins_pkt(pkt, %s + %zu, %zu, %zu, ", n->id_->c_str(), bit_offset >> 3, bit_offset & 0x7, bit_width);
        Function *store_fn = mod_->getFunction("bpf_dins_pkt");
        if (!store_fn) return mkstatus_(n, "unable to find function bpf_dins_pkt");
        LoadInst *skb_ptr = B.CreateLoad(skb_mem);
        Value *skb_ptr8 = B.CreateBitCast(skb_ptr, B.getInt8PtrTy());
        LoadInst *offset_ptr = B.CreateLoad(offset_mem);
        Value *skb_hdr_offset = B.CreateAdd(offset_ptr, B.getInt64(bit_offset >> 3));
        Value *rhs = B.CreateIntCast(pop_expr(), B.getInt64Ty(), false);
        B.CreateCall5(store_fn, skb_ptr8, skb_hdr_offset, B.getInt64(bit_offset & 0x7), B.getInt64(bit_width), rhs);
      } else {
        emit("bpf_dext_pkt(pkt, %s + %zu, %zu, %zu)", n->id_->c_str(), bit_offset >> 3, bit_offset & 0x7, bit_width);
        Function *load_fn = mod_->getFunction("bpf_dext_pkt");
        if (!load_fn) return mkstatus_(n, "unable to find function bpf_dext_pkt");
        LoadInst *skb_ptr = B.CreateLoad(skb_mem);
        Value *skb_ptr8 = B.CreateBitCast(skb_ptr, B.getInt8PtrTy());
        LoadInst *offset_ptr = B.CreateLoad(offset_mem);
        Value *skb_hdr_offset = B.CreateAdd(offset_ptr, B.getInt64(bit_offset >> 3));
        expr_ = B.CreateCall4(load_fn, skb_ptr8, skb_hdr_offset, B.getInt64(bit_offset & 0x7), B.getInt64(bit_width));
        // this generates extra trunc insns whereas the bpf.load fns already
        // trunc the values internally in the bpf interpeter
        //expr_ = B.CreateTrunc(pop_expr(), B.getIntNTy(bit_width));
      }
    } else {
      emit("pkt->start + pkt->offset + %s", n->id_->c_str());
      return mkstatus_(n, "unsupported");
    }
  }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_integer_expr_node(IntegerExprNode *n) {
  APInt val;
  StringRef(n->val_).getAsInteger(0, val);
  expr_ = ConstantInt::get(mod_->getContext(), val);
  if (n->bits_)
    expr_ = B.CreateIntCast(expr_, B.getIntNTy(n->bits_), false);
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_short_circuit_and(BinopExprNode *n) {
  Function *parent = B.GetInsertBlock()->getParent();
  BasicBlock *label_start = B.GetInsertBlock();
  BasicBlock *label_then = BasicBlock::Create(ctx(), "and.then", parent);
  BasicBlock *label_end = BasicBlock::Create(ctx(), "and.end", parent);

  TRY2(n->lhs_->accept(this));
  Value *neq_zero = B.CreateICmpNE(pop_expr(), B.getIntN(n->lhs_->bit_width_, 0));
  B.CreateCondBr(neq_zero, label_then, label_end);

  {
    BlockStack bstack(this, label_then);
    TRY2(n->rhs_->accept(this));
    expr_ = B.CreateICmpNE(pop_expr(), B.getIntN(n->rhs_->bit_width_, 0));
    B.CreateBr(label_end);
  }

  B.SetInsertPoint(label_end);

  PHINode *phi = B.CreatePHI(B.getInt1Ty(), 2);
  phi->addIncoming(B.getFalse(), label_start);
  phi->addIncoming(pop_expr(), label_then);
  expr_ = phi;

  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_short_circuit_or(BinopExprNode *n) {
  Function *parent = B.GetInsertBlock()->getParent();
  BasicBlock *label_start = B.GetInsertBlock();
  BasicBlock *label_then = BasicBlock::Create(ctx(), "or.then", parent);
  BasicBlock *label_end = BasicBlock::Create(ctx(), "or.end", parent);

  TRY2(n->lhs_->accept(this));
  Value *neq_zero = B.CreateICmpNE(pop_expr(), B.getIntN(n->lhs_->bit_width_, 0));
  B.CreateCondBr(neq_zero, label_end, label_then);

  {
    BlockStack bstack(this, label_then);
    TRY2(n->rhs_->accept(this));
    expr_ = B.CreateICmpNE(pop_expr(), B.getIntN(n->rhs_->bit_width_, 0));
    B.CreateBr(label_end);
  }

  B.SetInsertPoint(label_end);

  PHINode *phi = B.CreatePHI(B.getInt1Ty(), 2);
  phi->addIncoming(B.getTrue(), label_start);
  phi->addIncoming(pop_expr(), label_then);
  expr_ = phi;

  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_binop_expr_node(BinopExprNode *n) {
  if (n->op_ == Tok::TAND)
    return emit_short_circuit_and(n);
  if (n->op_ == Tok::TOR)
    return emit_short_circuit_or(n);

  TRY2(n->lhs_->accept(this));
  Value *lhs = pop_expr();
  TRY2(n->rhs_->accept(this));
  Value *rhs = B.CreateIntCast(pop_expr(), lhs->getType(), false);
  switch (n->op_) {
    case Tok::TCEQ: expr_ = B.CreateICmpEQ(lhs, rhs); break;
    case Tok::TCNE: expr_ = B.CreateICmpNE(lhs, rhs); break;
    case Tok::TXOR: expr_ = B.CreateXor(lhs, rhs); break;
    case Tok::TMOD: expr_ = B.CreateURem(lhs, rhs); break;
    case Tok::TCLT: expr_ = B.CreateICmpULT(lhs, rhs); break;
    case Tok::TCLE: expr_ = B.CreateICmpULE(lhs, rhs); break;
    case Tok::TCGT: expr_ = B.CreateICmpUGT(lhs, rhs); break;
    case Tok::TCGE: expr_ = B.CreateICmpUGE(lhs, rhs); break;
    case Tok::TPLUS: expr_ = B.CreateAdd(lhs, rhs); break;
    case Tok::TMINUS: expr_ = B.CreateSub(lhs, rhs); break;
    case Tok::TLAND: expr_ = B.CreateAnd(lhs, rhs); break;
    case Tok::TLOR: expr_ = B.CreateOr(lhs, rhs); break;
    default: return mkstatus_(n, "unsupported binary operator");
  }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_unop_expr_node(UnopExprNode *n) {
  TRY2(n->expr_->accept(this));
  switch (n->op_) {
    case Tok::TNOT: expr_ = B.CreateNot(pop_expr()); break;
    case Tok::TCMPL: expr_ = B.CreateNeg(pop_expr()); break;
    default: {}
  }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_bitop_expr_node(BitopExprNode *n) {
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_goto_expr_node(GotoExprNode *n) {
  if (n->id_->name_ == "DONE") {
    return mkstatus_(n, "use return statement instead");
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
  B.CreateBr(resolve_label(jump_label));
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_return_expr_node(ReturnExprNode *n) {
  TRY2(n->expr_->accept(this));
  Value *cast_1 = B.CreateIntCast(pop_expr(), cast<PointerType>(retval_->getType())->getElementType(), true);
  B.CreateStore(cast_1, retval_);
  B.CreateBr(resolve_label("DONE"));
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_table_lookup(MethodCallExprNode *n) {
  TableDeclStmtNode* table = scopes_->top_table()->lookup(n->id_->name_);
  IdentExprNode* arg0 = static_cast<IdentExprNode*>(n->args_.at(0).get());
  stringstream free_inst;
  IdentExprNode* arg1;
  StructVariableDeclStmtNode* arg1_type;

  auto table_fd_it = table_fds_.find(table);
  if (table_fd_it == table_fds_.end())
    return mkstatus_(n, "unable to find table %s in table_fds_", n->id_->c_str());

  Function *pseudo_fn = mod_->getFunction("llvm.bpf.pseudo");
  if (!pseudo_fn) return mkstatus_(n, "pseudo fd loader doesn't exist");
  Function *lookup_fn = mod_->getFunction("bpf_map_lookup_elem_");
  if (!lookup_fn) return mkstatus_(n, "bpf_map_lookup_elem_ undefined");

  CallInst *pseudo_call = B.CreateCall2(pseudo_fn, B.getInt64(BPF_PSEUDO_MAP_FD), B.getInt64(table_fd_it->second));
  Value *pseudo_map_fd = pseudo_call;

  TRY2(arg0->accept(this));
  Value *key_ptr = B.CreateBitCast(pop_expr(), B.getInt8PtrTy());

  expr_ = B.CreateCall2(lookup_fn, pseudo_map_fd, key_ptr);

  if (table->type_id()->name_ == "FIXED_MATCH" || table->type_id()->name_ == "INDEXED") {
    if (n->args_.size() == 2) {
      arg1 = static_cast<IdentExprNode*>(n->args_.at(1).get());
      arg1_type = static_cast<StructVariableDeclStmtNode*>(arg1->decl_);
      if (table->leaf_id()->name_ != arg1_type->struct_id_->name_) {
        return mkstatus_(n, "lookup pointer type mismatch %s != %s", table->leaf_id()->c_str(),
                        arg1_type->struct_id_->c_str());
      }
      auto it = vars_.find(arg1_type);
      if (it == vars_.end()) return mkstatus_(n, "Cannot locate variable %s in vars_ table", n->id_->c_str());
      expr_ = B.CreateBitCast(pop_expr(), cast<PointerType>(it->second->getType())->getElementType());
      B.CreateStore(pop_expr(), it->second);
    }
  } else {
    return mkstatus_(n, "lookup in table type %s unsupported", table->type_id()->c_str());
  }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_table_update(MethodCallExprNode *n) {
  TableDeclStmtNode* table = scopes_->top_table()->lookup(n->id_->name_);
  IdentExprNode* arg0 = static_cast<IdentExprNode*>(n->args_.at(0).get());
  IdentExprNode* arg1 = static_cast<IdentExprNode*>(n->args_.at(1).get());
  IdentExprNode* type0 = table->templates_.at(0).get();

  auto table_fd_it = table_fds_.find(table);
  if (table_fd_it == table_fds_.end())
    return mkstatus_(n, "unable to find table %s in table_fds_", n->id_->c_str());
  Function *pseudo_fn = mod_->getFunction("llvm.bpf.pseudo");
  if (!pseudo_fn) return mkstatus_(n, "pseudo fd loader doesn't exist");
  Function *update_fn = mod_->getFunction("bpf_map_update_elem_");
  if (!update_fn) return mkstatus_(n, "bpf_map_update_elem_ undefined");

  CallInst *pseudo_call = B.CreateCall2(pseudo_fn, B.getInt64(BPF_PSEUDO_MAP_FD),
                                        B.getInt64(table_fd_it->second));
  Value *pseudo_map_fd = pseudo_call;

  emit("%s* %s_ukey = &", type0->c_str(), n->id_->c_str());
  TRY2(arg0->accept(this));
  Value *key_ptr = B.CreateBitCast(pop_expr(), B.getInt8PtrTy());

  emitln(";");
  if (table->type_id()->name_ == "FIXED_MATCH" || table->type_id()->name_ == "INDEXED") {
    emit("bpf_table_update(pkt, TABLE_ID_%s, %s_ukey", n->id_->c_str(), n->id_->c_str());
    emit(", &");
    TRY2(arg1->accept(this));
    Value *value_ptr = B.CreateBitCast(pop_expr(), B.getInt8PtrTy());

    expr_ = B.CreateCall4(update_fn, pseudo_map_fd, key_ptr, value_ptr, B.getInt64(BPF_ANY));
    emitln(");");
  } else if (table->type_id()->name_ == "LPM") {
  }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_table_delete(MethodCallExprNode *n) {
  TableDeclStmtNode* table = scopes_->top_table()->lookup(n->id_->name_);
  IdentExprNode* arg0 = static_cast<IdentExprNode*>(n->args_.at(0).get());
  IdentExprNode* type0 = table->templates_.at(0).get();

  emit("%s* %s_dkey = &", type0->c_str(), n->id_->c_str());
  TRY2(arg0->accept(this));
  emitln(";");
  if (table->type_id()->name_ == "FIXED_MATCH" || table->type_id()->name_ == "INDEXED") {
    emit("bpf_table_delete(pkt, TABLE_ID_%s, %s_dkey", n->id_->c_str(), n->id_->c_str());
    emitln(");");
  } else if (table->type_id()->name_ == "LPM") {
  }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_channel_push_generic(MethodCallExprNode *n) {
  /* computation of orig_length of packet:
   * orig_lenth = pkt->length - (orig_offset - pkt->offset)
   * push_header(N) does pkt->length += N; pkt->offset -= N;
   * pop_header(N) does pg_may_access(N); pkt->length -=N; pkt->offset +=N;
   *
   * therefore push_header(); pop_header(); sequence is currently broken, ticket #930
   */
  emit("bpf_channel_push_packet(pkt");
  emit(")");
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_channel_push(MethodCallExprNode *n) {
  IdentExprNode* arg0 = static_cast<IdentExprNode*>(n->args_.at(0).get());
  StructVariableDeclStmtNode* arg0_type = static_cast<StructVariableDeclStmtNode*>(arg0->decl_);
  emit("bpf_channel_push_struct(pkt, STRUCTID_%s, &", arg0_type->struct_id_->c_str());
  TRY2(arg0->accept(this));
  emit(", sizeof(");
  TRY2(arg0->accept(this));
  emit("))");
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_log(MethodCallExprNode *n) {
  emitln("{ if (unlikely(pkt->capture)) {");
  emit("    bpf_capture(pkt, BPF_CAP_LOG, %d, ", n->line_);
  TRY2(n->args_[0]->accept(this));
  emit("); } }");
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_packet_forward(MethodCallExprNode *n) {
  emitln("pkt->arg1 &= ~1;");
  emit("bpf_forward(pkt, ");
  TRY2(n->args_[0]->accept(this));
  emit(")");
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_packet_replicate(MethodCallExprNode*n) {
  emitln("pkt->arg1 &= ~1;");
  emit("bpf_replicate(pkt, ");
  TRY2(n->args_[0]->accept(this));
  emit(",", n->id_->c_str());
  TRY2(n->args_[1]->accept(this));
  emit(")");
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_packet_clone_forward(MethodCallExprNode *n) {
  emitln("pkt->arg1 &= ~1;");
  emit("bpf_clone_forward(pkt, ");
  TRY2(n->args_[0]->accept(this));
  emit(")");
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_packet_forward_self(MethodCallExprNode *n) {
  emit("bpf_forward_self(pkt, ");
  TRY2(n->args_[0]->accept(this));
  emit(")");
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_packet_drop(MethodCallExprNode *n) {
  emit("bpf_drop(pkt)");
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_packet_push_header(MethodCallExprNode *n) {
  emit("if (unlikely(bpf_push_header(pkt, ");
  TRY2(n->args_[0]->accept(this));
  if (n->args_.size() == 1) {
    emit(", %zu, 0) != 0)) goto ERROR", n->args_[0]->struct_type_->bit_width_ >> 3);
  } else {
    emit(", %zu, ", n->args_[0]->struct_type_->bit_width_ >> 3);
    TRY2(n->args_[1]->accept(this));
    emit(") != 0)) goto ERROR");
  }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_packet_pop_header(MethodCallExprNode *n) {
  emit("if (unlikely(bpf_pop_header(pkt, ");
  if (n->args_[0]->typeof_ == ExprNode::STRUCT) {
    emit("%zu", n->args_[0]->struct_type_->bit_width_ >> 3);
  } else if (n->args_[0]->typeof_ == ExprNode::INTEGER) {
    TRY2(n->args_[0]->accept(this));
  }
  emit(", 0/*todo*/) != 0)) goto ERROR");
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_packet_push_vlan(MethodCallExprNode *n) {
  emit("if (unlikely(bpf_push_vlan(pkt, bpf_htons(0x8100/*ETH_P_8021Q*/), ");
  TRY2(n->args_[0]->accept(this));
  emit(") != 0)) goto ERROR");
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_packet_pop_vlan(MethodCallExprNode *n) {
  emit("if (unlikely(bpf_pop_vlan(pkt) != 0)) goto ERROR");
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_packet_rewrite_field(MethodCallExprNode *n) {
  TRY2(n->args_[1]->accept(this));
  TRY2(n->args_[0]->accept(this));
  emit(")");
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_atomic_add(MethodCallExprNode *n) {
  TRY2(n->args_[0]->accept(this));
  Value *lhs = B.CreateBitCast(pop_expr(), Type::getInt64PtrTy(ctx()));
  TRY2(n->args_[1]->accept(this));
  Value *rhs = B.CreateSExt(pop_expr(), B.getInt64Ty());
  AtomicRMWInst *atomic_inst = B.CreateAtomicRMW(AtomicRMWInst::Add, lhs, rhs, SequentiallyConsistent);
  atomic_inst->setVolatile(false);
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_cksum(MethodCallExprNode *n) {
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
        TRY2(n->args_[0]->accept(this));
        emit(", %zu))", bit_width);
      }
    } else {
      return mkstatus_(n, "cannot pg_cksum %d", n->args_[0]->typeof_);
    }
/**    emit("pg_cksum(");
    TRY2(n->args_[0]->accept(this));
    emit(", %zu)", n->args_[0]->struct_type_->bit_width_ >> 3);**/
  } else {
    return mkstatus_(n, "cannot pg_cksum %d", n->args_[0]->typeof_);
  }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_incr_cksum(MethodCallExprNode *n, size_t sz) {
  Value *is_pseudo;
  string csum_fn_str;
  if (n->args_.size() == 4) {
    TRY2(n->args_[3]->accept(this));
    is_pseudo = B.CreateIntCast(B.CreateIsNotNull(pop_expr()), B.getInt64Ty(), false);
    csum_fn_str = "bpf_l4_csum_replace_";
  } else {
    is_pseudo = B.getInt64(0);
    csum_fn_str = "bpf_l3_csum_replace_";
  }

  TRY2(n->args_[2]->accept(this));
  Value *new_val = B.CreateZExt(pop_expr(), B.getInt64Ty());
  TRY2(n->args_[1]->accept(this));
  Value *old_val = B.CreateZExt(pop_expr(), B.getInt64Ty());
  TRY2(n->args_[0]->accept(this));
  Value *offset = B.CreateZExt(pop_expr(), B.getInt64Ty());

  Function *csum_fn = mod_->getFunction(csum_fn_str);
  if (!csum_fn) return mkstatus_(n, "Undefined built-in %s", csum_fn_str.c_str());

  // flags = (is_pseudo << 4) | sizeof(old_val)
  Value *flags_lower = B.getInt64(sz ? sz : bits_to_size(n->args_[1]->bit_width_));
  Value *flags_upper = B.CreateShl(is_pseudo, B.getInt64(4));
  Value *flags = B.CreateOr(flags_upper, flags_lower);

  VariableDeclStmtNode *skb_decl;
  Value *skb_mem;
  TRY2(lookup_var(n, "skb", scopes_->top_var(), &skb_decl, &skb_mem));
  LoadInst *skb_ptr = B.CreateLoad(skb_mem);
  Value *skb_ptr8 = B.CreateBitCast(skb_ptr, B.getInt8PtrTy());

  expr_ = B.CreateCall5(csum_fn, skb_ptr8, offset, old_val, new_val, flags);

  // if (n->args_.size() == 3) {
  //   /* ip checksum */
  //   emit("bpf_ntohs(bpf_csum_replace4(bpf_htons(");
  //   TRY2(n->args_[0]->accept(this));
  //   emit("), bpf_htonl(");
  //   TRY2(n->args_[1]->accept(this));
  //   emit("), bpf_htonl(");
  //   TRY2(n->args_[2]->accept(this));
  //   emit(")))");
  // } else {
  //   /* L4 checksum */
  //   emit("(");
  //   /* part of pseudo header */
  //   TRY2(n->args_[3]->accept(this));
  //   emit(" ? ");
  //   emit("((pkt->hw_csum == 1) ? ");
  //   /* CHECKSUM_PARTIAL update pseudo only */
  //   emit("bpf_ntohs(bpf_pseudo_csum_replace4(bpf_htons(");
  //   TRY2(n->args_[0]->accept(this));
  //   emit("), bpf_htonl(");
  //   TRY2(n->args_[1]->accept(this));
  //   emit("), bpf_htonl(");
  //   TRY2(n->args_[2]->accept(this));
  //   emit(")))");
  //   emit(" : ");
  //   /* CHECKSUM_NONE update normally */
  //   emit("bpf_ntohs(bpf_csum_replace4(bpf_htons(");
  //   TRY2(n->args_[0]->accept(this));
  //   emit("), bpf_htonl(");
  //   TRY2(n->args_[1]->accept(this));
  //   emit("), bpf_htonl(");
  //   TRY2(n->args_[2]->accept(this));
  //   emit(")))");
  //   emit(")");
  //   emit(" : ");
  //   /* not part of pseudo */
  //   emit("((pkt->hw_csum != 1) ? ");
  //   /* CHECKSUM_NONE updata normally */
  //   emit("bpf_ntohs(bpf_csum_replace4(bpf_htons(");
  //   TRY2(n->args_[0]->accept(this));
  //   emit("), bpf_htonl(");
  //   TRY2(n->args_[1]->accept(this));
  //   emit("), bpf_htonl(");
  //   TRY2(n->args_[2]->accept(this));
  //   emit(")))");
  //   emit(" : ");
  //   /* CHECKSUM_PARTIAL no-op */
  //   TRY2(n->args_[0]->accept(this));
  //   emit("))");
  // }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_lb_hash(MethodCallExprNode *n) {
  emit("pg_lb_hash(");
  TRY2(n->args_[0]->accept(this));
  emit(", ");
  TRY2(n->args_[1]->accept(this));
  emit(")");
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_sizeof(MethodCallExprNode *n) {
  if (n->args_[0]->typeof_ == ExprNode::STRUCT) {
    if (n->args_[0]->struct_type_->id_->name_ == "_Packet") {
      //emit("PG_SIZEOF(pkt)");
      emit("(int)pkt->length");
    } else {
      emit("%zu", n->args_[0]->struct_type_->bit_width_ >> 3);
      expr_ = B.getInt64(n->args_[0]->struct_type_->bit_width_ >> 3);
    }
  } else if (n->args_[0]->typeof_ == ExprNode::INTEGER) {
    if (n->args_[0]->struct_type_) {
      expr_ = B.getInt64(n->args_[0]->struct_type_->bit_width_ >> 3);
    } else {
      emit("%zu", n->args_[0]->bit_width_ >> 3);
      expr_ = B.getInt64(n->args_[0]->bit_width_ >> 3);
    }
  }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_get_usec_time(MethodCallExprNode *n) {
  emit("bpf_get_usec_time()");
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_forward_to_vnf(MethodCallExprNode*n) {
  emitln("pkt->arg1 |= 1;");
  emit("pkt->arg2 = ");
  TRY2(n->args_[0]->accept(this));
  emitln(";");
  emit("bpf_forward_to_plum(pkt, ");
  TRY2(n->args_[1]->accept(this));
  emit(")");

  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_forward_to_group(MethodCallExprNode *n) {

  emit("pkt->arg2 = ");
  TRY2(n->args_[0]->accept(this));
  emitln(";");
  emitln("pkt->arg3 = pkt->plum_id;");
  emit("bpf_forward_to_plum(pkt, ");
  emit("1/*TUNNEL_PLUM_ID*/");
  emit(")");

  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_method_call_expr_node(MethodCallExprNode *n) {
  free_instructions_.push_back(vector<string>());

  if (!n->block_->stmts_.empty()) {
    ++indent_;
    emitln("{");
  }

  if (n->id_->sub_name_.size()) {
    if (n->id_->sub_name_ == "lookup") {
      TRY2(emit_table_lookup(n));
    } else if (n->id_->sub_name_ == "update") {
      TRY2(emit_table_update(n));
    } else if (n->id_->sub_name_ == "delete") {
      TRY2(emit_table_delete(n));
    } else if (n->id_->sub_name_ == "replicate" && n->id_->name_ == "pkt") {
      TRY2(emit_packet_replicate(n));
    } else if (n->id_->sub_name_ == "forward" && n->id_->name_ == "pkt") {
      TRY2(emit_packet_forward(n));
    } else if (n->id_->sub_name_ == "forward_self" && n->id_->name_ == "pkt") {
      TRY2(emit_packet_forward_self(n));
    } else if (n->id_->sub_name_ == "push_header" && n->id_->name_ == "pkt") {
      TRY2(emit_packet_push_header(n));
    } else if (n->id_->sub_name_ == "pop_header" && n->id_->name_ == "pkt") {
      TRY2(emit_packet_pop_header(n));
    } else if (n->id_->sub_name_ == "push_vlan" && n->id_->name_ == "pkt") {
      TRY2(emit_packet_push_vlan(n));
    } else if (n->id_->sub_name_ == "pop_vlan" && n->id_->name_ == "pkt") {
      TRY2(emit_packet_pop_vlan(n));
    } else if (n->id_->sub_name_ == "rewrite_field" && n->id_->name_ == "pkt") {
      TRY2(emit_packet_rewrite_field(n));
    } else if (n->id_->sub_name_ == "clone_forward" && n->id_->name_ == "pkt") {
      TRY2(emit_packet_clone_forward(n));
    }
  } else if (n->id_->name_ == "atomic_add") {
    TRY2(emit_atomic_add(n));
  } else if (n->id_->name_ == "log") {
    TRY2(emit_log(n));
  } else if (n->id_->name_ == "cksum") {
    TRY2(emit_cksum(n));
  } else if (n->id_->name_ == "incr_cksum_u16") {
    TRY2(emit_incr_cksum(n, 2));
  } else if (n->id_->name_ == "incr_cksum_u32") {
    TRY2(emit_incr_cksum(n, 4));
  } else if (n->id_->name_ == "incr_cksum") {
    TRY2(emit_incr_cksum(n));
  } else if (n->id_->name_ == "lb_hash") {
    TRY2(emit_lb_hash(n));
  } else if (n->id_->name_ == "sizeof") {
    TRY2(emit_sizeof(n));
  } else if (n->id_->name_ == "get_usec_time") {
    TRY2(emit_get_usec_time(n));
  } else if (n->id_->name_ == "channel_push") {
    TRY2(emit_channel_push(n));
  } else if (n->id_->name_ == "channel_push_generic") {
    TRY2(emit_channel_push_generic(n));
  } else if (n->id_->name_ == "forward_to_vnf") {
    TRY2(emit_forward_to_vnf(n));
  } else if (n->id_->name_ == "forward_to_group") {
    TRY2(emit_forward_to_group(n));
  } else {
    TRY2(n->id_->accept(this));
    emit("(");
    for (auto it = n->args_.begin(); it != n->args_.end(); ++it) {
      TRY2((*it)->accept(this));
      if (it + 1 != n->args_.end()) {
        emit(", ");
      }
    }
  }
  TRY2(n->block_->accept(this));
  return mkstatus(0);
}

/// on_match
StatusTuple CodegenLLVM::visit_match_decl_stmt_node(MatchDeclStmtNode *n) {
  if (n->formals_.size() != 1)
    return mkstatus_(n, "on_match expected 1 arguments, %zu given", n->formals_.size());
  StructVariableDeclStmtNode* leaf_n = static_cast<StructVariableDeclStmtNode*>(n->formals_.at(0).get());
  if (!leaf_n)
    return mkstatus_(n, "invalid parameter type");
  // lookup result variable
  auto result_decl = scopes_->current_var()->lookup("_result", false);
  if (!result_decl) return mkstatus_(n, "unable to find _result built-in");
  auto result = vars_.find(result_decl);
  if (result == vars_.end()) return mkstatus_(n, "unable to find memory for _result built-in");
  vars_[leaf_n] = result->second;

  Value *load_1 = B.CreateLoad(result->second);
  Value *is_null = B.CreateIsNotNull(load_1);

  Function *parent = B.GetInsertBlock()->getParent();
  BasicBlock *label_then = BasicBlock::Create(ctx(), "onvalid.then", parent);
  BasicBlock *label_end = BasicBlock::Create(ctx(), "onvalid.end", parent);
  B.CreateCondBr(is_null, label_then, label_end);

  {
    BlockStack bstack(this, label_then);
    TRY2(n->block_->accept(this));
    if (!B.GetInsertBlock()->getTerminator())
      B.CreateBr(label_end);
  }

  B.SetInsertPoint(label_end);
  return mkstatus(0);
}

/// on_miss
StatusTuple CodegenLLVM::visit_miss_decl_stmt_node(MissDeclStmtNode *n) {
  if (n->formals_.size() != 0)
    return mkstatus_(n, "on_match expected 0 arguments, %zu given", n->formals_.size());
  auto result_decl = scopes_->current_var()->lookup("_result", false);
  if (!result_decl) return mkstatus_(n, "unable to find _result built-in");
  auto result = vars_.find(result_decl);
  if (result == vars_.end()) return mkstatus_(n, "unable to find memory for _result built-in");

  Value *load_1 = B.CreateLoad(result->second);
  Value *is_null = B.CreateIsNull(load_1);

  Function *parent = B.GetInsertBlock()->getParent();
  BasicBlock *label_then = BasicBlock::Create(ctx(), "onvalid.then", parent);
  BasicBlock *label_end = BasicBlock::Create(ctx(), "onvalid.end", parent);
  B.CreateCondBr(is_null, label_then, label_end);

  {
    BlockStack bstack(this, label_then);
    TRY2(n->block_->accept(this));
    if (!B.GetInsertBlock()->getTerminator())
      B.CreateBr(label_end);
  }

  B.SetInsertPoint(label_end);
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_failure_decl_stmt_node(FailureDeclStmtNode *n) {
  if (n->formals_.size() != 1)
    return mkstatus_(n, "on_failure expected 1 argument, %zu given", n->formals_.size());
  StructVariableDeclStmtNode* key_n = static_cast<StructVariableDeclStmtNode*>(n->formals_.at(0).get());
  ++indent_;
  emitln("/*if ((unsigned long)%s_element >= (unsigned long)-4095) {", n->id_->name_.c_str());
  emitln("%s* %s%s = %s_key;", key_n->struct_id_->c_str(),
         key_n->scope_id(), key_n->id_->c_str(), n->id_->c_str());
  TRY2(n->block_->accept(this));
  --indent_;
  emitln("");
  emit("}*/");
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_expr_stmt_node(ExprStmtNode *n) {
  TRY2(n->expr_->accept(this));
  expr_ = nullptr;
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_struct_variable_decl_stmt_node(StructVariableDeclStmtNode *n) {
  if (n->struct_id_->name_ == "" || n->struct_id_->name_[0] == '_') {
    return mkstatus(0);
  }
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
          TRY2(asn->rhs_->accept(this));
          emit(");");
        }
      }
    }
  } else {
    StructDeclStmtNode *decl = scopes_->top_struct()->lookup(n->struct_id_->name_);
    if (!decl) return mkstatus_(n, "Cannot find struct %s decl", n->id_->c_str());

    auto it = structs_.find(decl);
    if (it == structs_.end()) return mkstatus_(n, "Cannot find struct %s decl", n->id_->c_str());
    Type *stype = n->is_pointer() ? PointerType::get(it->second, 0) : (PointerType *)it->second;
    AllocaInst *ptr_a = new AllocaInst(stype, nullptr, "", entry_bb_);
    vars_[n] = ptr_a;
    if (n->is_pointer()) {
      if (n->id_->name_ == "_result") {
        // special case for capturing the return value of a previous method call
        Value *cast_1 = B.CreateBitCast(pop_expr(), stype);
        B.CreateStore(cast_1, ptr_a);
      } else {
        ConstantPointerNull *const_null = ConstantPointerNull::get(cast<PointerType>(stype));
        B.CreateStore(const_null, ptr_a);
      }
    } else {
      B.CreateMemSet(ptr_a, B.getInt8(0), B.getInt64(decl->bit_width_ >> 3), 1);
      emit("%s %s%s = {};", n->struct_id_->c_str(), n->scope_id(), n->id_->c_str());
      if (!n->init_.empty()) {
        for (auto it = n->init_.begin(); it != n->init_.end(); ++it) {
          emit(" ");
          TRY2((*it)->accept(this));
          emit(";");
        }
      }
    }
  }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_integer_variable_decl_stmt_node(IntegerVariableDeclStmtNode *n) {
  if (!B.GetInsertBlock())
    return mkstatus(0);
  if (n->id_->name_ == "timer_delay")
    return mkstatus(0);
  emit_comment(n);
  emit("%s %s%s", bits_to_uint(n->bit_width_), n->scope_id(), n->id_->c_str());

  // uintX var = init
  AllocaInst *ptr_a = new AllocaInst(B.getIntNTy(n->bit_width_), nullptr, n->id_->name_, entry_bb_);
  vars_[n] = ptr_a;

  // todo
  if (!n->scope_id_.empty())
    emit(" = 0");
  if (!n->init_.empty()) {
    emit("; ");
    TRY2(n->init_[0]->accept(this));
  }
  emit(";");
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_struct_decl_stmt_node(StructDeclStmtNode *n) {
  ++indent_;
  StructType *struct_type = StructType::create(ctx(), "struct." + n->id_->name_);
  vector<Type *> fields;
  for (auto it = n->stmts_.begin(); it != n->stmts_.end(); ++it)
    fields.push_back(B.getIntNTy((*it)->bit_width_));
  struct_type->setBody(fields, n->is_packed());
  structs_[n] = struct_type;
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_parser_state_stmt_node(ParserStateStmtNode *n) {
  string jump_label = n->scoped_name() + "_continue";
  BasicBlock *label_entry = resolve_label(jump_label);
  B.SetInsertPoint(label_entry);
  if (n->next_state_)
    TRY2(n->next_state_->accept(this));
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_timer_decl_stmt_node(TimerDeclStmtNode *n) {
  auto scope = scopes_->current_state();
  scopes_->set_current(n->scope_);
  TRY2(n->block_->accept(this));
  scopes_->set_current(scope);
  return mkstatus(0);
}
StatusTuple CodegenLLVM::visit_state_decl_stmt_node(StateDeclStmtNode *n) {
  if (!n->id_) {
    return mkstatus(0);
  }
  string jump_label = n->scoped_name();
  BasicBlock *label_entry = resolve_label(jump_label);
  B.SetInsertPoint(label_entry);

  auto it = n->subs_.begin();

  auto scope = scopes_->current_state();
  scopes_->set_current(it->scope_);

  for (auto in = n->init_.begin(); in != n->init_.end(); ++in) {
    TRY2((*in)->accept(this));
  }

  if (n->subs_.size() == 1 && it->id_->name_ == "") {
    // this is not a multistate protocol, emit everything and finish
    TRY2(it->block_->accept(this));
    if (n->parser_) {
      B.CreateBr(resolve_label(jump_label + "_continue"));
      TRY2(n->parser_->accept(this));
    }
  } else {
    return mkstatus_(n, "unsupported");
    if (n->parser_) {
      for (auto it2 = n->subs_.begin(); it2 != n->subs_.end(); ++it2) {
        proto_rewrites_[it2->id_->full_name()] = n->scoped_name() + "_" + it2->id_->name_;
      }
      TRY2(n->parser_->accept(this));
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
      TRY2(it->block_->accept(this));
      if (it->parser_) {
        emitln("");
        TRY2(it->parser_->accept(this));
      }
      --indent_;
      emitln("");
      emitln("}");

      scopes_->set_current(scope);
    }
  }

  scopes_->set_current(scope);

  --indent_;
  emitln("");
  emit("}");
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_table_decl_stmt_node(TableDeclStmtNode *n) {
  if (n->table_type_->name_ == "Table"
      || n->table_type_->name_ == "SharedTable") {
    if (n->templates_.size() != 4)
      return mkstatus_(n, "%s expected 4 arguments, %zu given", n->table_type_->c_str(), n->templates_.size());
    auto key = scopes_->top_struct()->lookup(n->key_id()->name_, /*search_local*/true);
    if (!key) return mkstatus_(n, "cannot find key %s", n->key_id()->name_.c_str());
    auto leaf = scopes_->top_struct()->lookup(n->leaf_id()->name_, /*search_local*/true);
    if (!leaf) return mkstatus_(n, "cannot find leaf %s", n->leaf_id()->name_.c_str());

    int map_type = BPF_MAP_TYPE_UNSPEC;
    if (n->type_id()->name_ == "FIXED_MATCH")
      map_type = BPF_MAP_TYPE_HASH;
    else if (n->type_id()->name_ == "INDEXED")
      map_type = BPF_MAP_TYPE_ARRAY;
    else
      return mkstatus_(n, "Table type %s not implemented", n->type_id()->name_.c_str());

    StructType *decl_struct = mod_->getTypeByName("struct." + n->id_->name_);
    if (!decl_struct)
      decl_struct = StructType::create(ctx(), "struct." + n->id_->name_);
    if (decl_struct->isOpaque())
      decl_struct->setBody(std::vector<Type *>({Type::getInt32Ty(ctx()), Type::getInt32Ty(ctx()),
                                                Type::getInt32Ty(ctx()), Type::getInt32Ty(ctx())}),
                           /*isPacked=*/false);
    GlobalVariable *decl_gvar = new GlobalVariable(*mod_, decl_struct, false,
                                                   GlobalValue::ExternalLinkage, 0, n->id_->name_);
    decl_gvar->setSection("maps");
    decl_gvar->setAlignment(4);
    vector<Constant *> struct_init = { B.getInt32(map_type), B.getInt32(key->bit_width_ / 8),
                                       B.getInt32(leaf->bit_width_ / 8), B.getInt32(n->size_)};
    Constant *const_struct = ConstantStruct::get(decl_struct, struct_init);
    decl_gvar->setInitializer(const_struct);
    tables_[n] = decl_gvar;

    int map_fd = bpf_create_map(map_type, key->bit_width_ / 8, leaf->bit_width_ / 8, n->size_);
    if (map_fd >= 0 || !ENABLE_RELOCATIONS)
      table_fds_[n] = map_fd;
  } else {
    return mkstatus_(n, "Table %s not implemented", n->table_type_->name_.c_str());
  }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit(Node* root) {
  BlockStmtNode* b = static_cast<BlockStmtNode*>(root);


  scopes_->set_current(scopes_->top_state());
  scopes_->set_current(scopes_->top_var());

  TRY2(print_header());

  TRY2(b->ver_.accept(this));

  for (auto it = scopes_->top_table()->obegin(); it != scopes_->top_table()->oend(); ++it) {
    TRY2((*it)->accept(this));
    emit("\n");
  }

  TRY2(print_parser());

  return mkstatus(0);
}

StatusTuple CodegenLLVM::print_timer() {
  // visit timers
  ++indent_;
  emitln("PG_PARSE_DECL(timer) {");
  emitln("uint32_t timer_delay = 0;");
  // visit function scoped variables
  for (auto it = scopes_->current_var()->obegin(); it != scopes_->current_var()->oend(); ++it) {
    TRY2((*it)->accept(this));
    emitln("");
  }
  for (auto it = scopes_->top_timer()->obegin(); it != scopes_->top_timer()->oend(); ++it) {
    TRY2((*it)->accept(this));
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
  return mkstatus(0);
}

StatusTuple CodegenLLVM::print_parser() {
  auto skbuff_decl = scopes_->top_struct()->lookup("_skbuff");
  if (!skbuff_decl) return mkstatus(-1, "could not find built-in struct decl _skbuff");
  auto struct_it = structs_.find(skbuff_decl);
  if (struct_it == structs_.end()) return mkstatus(-1, "could not find built-in type _skbuff");

  // int parse(struct sk_buff *skb)
  FunctionType *parse_fn_type = FunctionType::get(B.getInt32Ty(),
                                                  vector<Type *>({PointerType::get(struct_it->second, 0)}),
                                                  /*isVarArg=*/false);

  Function *prog = mod_->getFunction("main");
  if (!prog) {
    prog = Function::Create(parse_fn_type, GlobalValue::ExternalLinkage, "main", mod_);
    if (section_.empty()) return mkstatus(-1, "Empty section pragma");
    prog->setSection(section_);
  }

  entry_bb_ = BasicBlock::Create(ctx(), "entry", prog);
  labels_["entry"] = entry_bb_;

  B.SetInsertPoint(entry_bb_);

  auto args = prog->arg_begin();
  Value *skb_arg = args++;
  skb_arg->setName("skb");
  auto skb = scopes_->top_var()->lookup("skb", true);
  if (!skb) return mkstatus(-1, "unable to find declaration of built-in skb");
  Type *stype = PointerType::get(struct_it->second, 0);
  AllocaInst *ptr_skb = new AllocaInst(stype, nullptr, "skb", entry_bb_);
  ptr_skb->setAlignment(4);
  B.CreateStore(skb_arg, ptr_skb);

  retval_ = new AllocaInst(B.getInt32Ty(), nullptr, "ret", entry_bb_);
  B.CreateStore(B.getInt32(0), retval_);

  vars_[skb] = ptr_skb;

  BasicBlock *label_return = resolve_label("DONE");

  ++indent_;
  emitln("PG_PARSE_DECL(parse) {");
  /* emitln("uint8_t *pp;"); */
  emitln("uint32_t parsed_bytes = 0;");
  //emitln("uint16_t orig_offset = 0;/*pkt->offset;*/");

  // visit function scoped variables
  {
    BlockStack bstack(this, entry_bb_);
    B.SetInsertPoint(entry_bb_);
    for (auto it = scopes_->current_var()->obegin(); it != scopes_->current_var()->oend(); ++it)
      TRY2((*it)->accept(this));
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
    emitln("");
    TRY2((*it)->accept(this));
  }

  B.SetInsertPoint(entry_bb_);
  B.CreateBr(resolve_label("s1_INIT"));

  B.SetInsertPoint(label_return);
  expr_ = B.CreateLoad(retval_);
  B.CreateRet(pop_expr());

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
  return mkstatus(0);
}

StatusTuple CodegenLLVM::print_header() {
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
  emitln("#define PG_SIZEOF(_pkt) ((int)_pkt->length - (int)_pkt->offset + 0/*orig_offset*/)");

  GlobalVariable *gvar_license = new GlobalVariable(*mod_, ArrayType::get(Type::getInt8Ty(ctx()), 4),
                                                    false, GlobalValue::ExternalLinkage, 0, "_license");
  gvar_license->setSection("license");
  gvar_license->setAlignment(1);
  gvar_license->setInitializer(ConstantDataArray::getString(ctx(), "GPL", true));

  Function *pseudo_fn = mod_->getFunction("llvm.bpf.pseudo");
  if (!pseudo_fn) {
    pseudo_fn = Function::Create(
        FunctionType::get(B.getInt64Ty(), vector<Type *>({B.getInt64Ty(), B.getInt64Ty()}), false),
        GlobalValue::ExternalLinkage, "llvm.bpf.pseudo", mod_);
  }

  int i = 0;
  // declare structures
  for (auto it = scopes_->top_struct()->obegin(); it != scopes_->top_struct()->oend(); ++it) {
    if ((*it)->id_->name_ == "_Packet")
      continue;
    TRY2((*it)->accept(this));
    emit(";\n");
    emitln("#define STRUCTID_%s %d", (*it)->id_->c_str(), i++);
  }
  emitln("#define STRUCTID_generic %d", i);
  return mkstatus(0);
}

int CodegenLLVM::get_table_fd(const std::string &name) const {
  TableDeclStmtNode *table = scopes_->top_table()->lookup(name);
  if (!table)
    return -1;

  auto table_fd_it = table_fds_.find(table);
  if (table_fd_it == table_fds_.end())
    return -1;

  return table_fd_it->second;
}

LLVMContext & CodegenLLVM::ctx() const {
  return mod_->getContext();
}

Constant * CodegenLLVM::const_int(uint64_t val, unsigned bits, bool is_signed) {
  return ConstantInt::get(ctx(), APInt(bits, val, is_signed));
}

Value * CodegenLLVM::pop_expr() {
  Value *ret = expr_;
  expr_ = nullptr;
  return ret;
}

BasicBlock * CodegenLLVM::resolve_label(const string &label) {
  auto it = labels_.find(label);
  if (it != labels_.end()) return it->second;
  Function *parent = B.GetInsertBlock()->getParent();
  BasicBlock *label_new = BasicBlock::Create(ctx(), label, parent);
  labels_[label] = label_new;
  return label_new;
}

}  // namespace cc
}  // namespace ebpf
