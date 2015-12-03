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
#include "codegen_llvm.h"
#include "lexer.h"
#include "table_desc.h"
#include "type_helper.h"
#include "linux/bpf.h"
#include "libbpf.h"

namespace ebpf {
namespace cc {

using namespace llvm;

using std::for_each;
using std::make_tuple;
using std::map;
using std::pair;
using std::set;
using std::string;
using std::stringstream;
using std::to_string;
using std::vector;

// can't forward declare IRBuilder in .h file (template with default
// parameters), so cast it instead :(
#define B (*((IRBuilder<> *)this->b_))

// Helper class to push/pop the insert block
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

// Helper class to push/pop switch statement insert block
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

CodegenLLVM::CodegenLLVM(llvm::Module *mod, Scopes *scopes, Scopes *proto_scopes)
  : out_(stdout), mod_(mod), indent_(0), tmp_reg_index_(0), scopes_(scopes),
    proto_scopes_(proto_scopes), expr_(nullptr) {
  b_ = new IRBuilder<>(ctx());
}
CodegenLLVM::~CodegenLLVM() {
  delete b_;
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

StatusTuple CodegenLLVM::visit_block_stmt_node(BlockStmtNode *n) {

  // enter scope
  if (n->scope_)
    scopes_->push_var(n->scope_);

  if (!n->stmts_.empty()) {
    for (auto it = n->stmts_.begin(); it != n->stmts_.end(); ++it)
      TRY2((*it)->accept(this));
  }
  // exit scope
  if (n->scope_)
    scopes_->pop_var();

  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_if_stmt_node(IfStmtNode *n) {
  Function *parent = B.GetInsertBlock()->getParent();
  BasicBlock *label_then = BasicBlock::Create(ctx(), "if.then", parent);
  BasicBlock *label_else = n->false_block_ ? BasicBlock::Create(ctx(), "if.else", parent) : nullptr;
  BasicBlock *label_end = BasicBlock::Create(ctx(), "if.end", parent);

  TRY2(n->cond_->accept(this));
  Value *is_not_null = B.CreateIsNotNull(pop_expr());

  if (n->false_block_)
    B.CreateCondBr(is_not_null, label_then, label_else);
  else
    B.CreateCondBr(is_not_null, label_then, label_end);

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
  if (pred_empty(label_end)) {
    B.SetInsertPoint(resolve_label("DONE"));
    label_end->eraseFromParent();
  }
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
      auto it = vars_.find(n->decl_);
      if (it == vars_.end()) return mkstatus_(n, "Cannot locate variable %s in vars_ table", n->c_str());
      expr_ = n->is_lhs() ? it->second : (Value *)B.CreateLoad(it->second);
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
    TRY2(n->lhs_->accept(this));
    emit(" = (");
    TRY2(n->lhs_->accept(this));
    emit(" & ~((((%s)1 << %d) - 1) << %d)) | (", bits_to_uint(n->lhs_->bit_width_),
         n->bitop_->bit_width_, n->bitop_->bit_offset_);
    TRY2(n->rhs_->accept(this));
    emit(" << %d)", n->bitop_->bit_offset_);
    return mkstatus_(n, "unsupported");
  } else {
    if (n->lhs_->flags_[ExprNode::PROTO]) {
      // auto f = n->lhs_->struct_type_->field(n->id_->sub_name_);
      // emit("bpf_dins(%s%s + %zu, %zu, %zu, ", n->id_->decl_->scope_id(), n->id_->c_str(),
      //      f->bit_offset_ >> 3, f->bit_offset_ & 0x7, f->bit_width_);
      // TRY2(n->rhs_->accept(this));
      // emit(")");
      return mkstatus_(n, "unsupported");
    } else {
      TRY2(n->rhs_->accept(this));
      if (n->lhs_->is_pkt()) {
        TRY2(n->lhs_->accept(this));
      } else {
        Value *rhs = pop_expr();
        TRY2(n->lhs_->accept(this));
        Value *lhs = pop_expr();
        if (!n->rhs_->is_ref())
          rhs = B.CreateIntCast(rhs, cast<PointerType>(lhs->getType())->getElementType(), false);
        B.CreateStore(rhs, lhs);
      }
    }
  }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::lookup_var(Node *n, const string &name, Scopes::VarScope *scope,
                                    VariableDeclStmtNode **decl, Value **mem) const {
  *decl = scope->lookup(name, SCOPE_GLOBAL);
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
  TRY2(lookup_var(n, "skb", scopes_->current_var(), &skb_decl, &skb_mem));
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
        B.CreateCall(store_fn, vector<Value *>({skb_ptr8, skb_hdr_offset, B.getInt64(bit_offset & 0x7),
                                               B.getInt64(bit_width), rhs}));
      } else {
        emit("bpf_dext_pkt(pkt, %s + %zu, %zu, %zu)", n->id_->c_str(), bit_offset >> 3, bit_offset & 0x7, bit_width);
        Function *load_fn = mod_->getFunction("bpf_dext_pkt");
        if (!load_fn) return mkstatus_(n, "unable to find function bpf_dext_pkt");
        LoadInst *skb_ptr = B.CreateLoad(skb_mem);
        Value *skb_ptr8 = B.CreateBitCast(skb_ptr, B.getInt8PtrTy());
        LoadInst *offset_ptr = B.CreateLoad(offset_mem);
        Value *skb_hdr_offset = B.CreateAdd(offset_ptr, B.getInt64(bit_offset >> 3));
        expr_ = B.CreateCall(load_fn, vector<Value *>({skb_ptr8, skb_hdr_offset,
                                                      B.getInt64(bit_offset & 0x7), B.getInt64(bit_width)}));
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

StatusTuple CodegenLLVM::visit_string_expr_node(StringExprNode *n) {
  if (n->is_lhs()) return mkstatus_(n, "cannot assign to a string");

  Value *global = B.CreateGlobalString(n->val_);
  Value *ptr = new AllocaInst(B.getInt8Ty(), B.getInt64(n->val_.size() + 1), "", resolve_entry_stack());
  B.CreateMemCpy(ptr, global, n->val_.size() + 1, 1);
  expr_ = ptr;

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
  Function *parent = B.GetInsertBlock()->getParent();
  Value *cast_1 = B.CreateIntCast(pop_expr(), parent->getReturnType(), true);
  B.CreateStore(cast_1, retval_);
  B.CreateBr(resolve_label("DONE"));
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_table_lookup(MethodCallExprNode *n) {
  TableDeclStmtNode* table = scopes_->top_table()->lookup(n->id_->name_);
  IdentExprNode* arg0 = static_cast<IdentExprNode*>(n->args_.at(0).get());
  IdentExprNode* arg1;
  StructVariableDeclStmtNode* arg1_type;

  auto table_fd_it = table_fds_.find(table);
  if (table_fd_it == table_fds_.end())
    return mkstatus_(n, "unable to find table %s in table_fds_", n->id_->c_str());

  Function *pseudo_fn = mod_->getFunction("llvm.bpf.pseudo");
  if (!pseudo_fn) return mkstatus_(n, "pseudo fd loader doesn't exist");
  Function *lookup_fn = mod_->getFunction("bpf_map_lookup_elem_");
  if (!lookup_fn) return mkstatus_(n, "bpf_map_lookup_elem_ undefined");

  CallInst *pseudo_call = B.CreateCall(pseudo_fn, vector<Value *>({B.getInt64(BPF_PSEUDO_MAP_FD),
                                                                  B.getInt64(table_fd_it->second)}));
  Value *pseudo_map_fd = pseudo_call;

  TRY2(arg0->accept(this));
  Value *key_ptr = B.CreateBitCast(pop_expr(), B.getInt8PtrTy());

  expr_ = B.CreateCall(lookup_fn, vector<Value *>({pseudo_map_fd, key_ptr}));

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

  auto table_fd_it = table_fds_.find(table);
  if (table_fd_it == table_fds_.end())
    return mkstatus_(n, "unable to find table %s in table_fds_", n->id_->c_str());
  Function *pseudo_fn = mod_->getFunction("llvm.bpf.pseudo");
  if (!pseudo_fn) return mkstatus_(n, "pseudo fd loader doesn't exist");
  Function *update_fn = mod_->getFunction("bpf_map_update_elem_");
  if (!update_fn) return mkstatus_(n, "bpf_map_update_elem_ undefined");

  CallInst *pseudo_call = B.CreateCall(pseudo_fn, vector<Value *>({B.getInt64(BPF_PSEUDO_MAP_FD),
                                        B.getInt64(table_fd_it->second)}));
  Value *pseudo_map_fd = pseudo_call;

  TRY2(arg0->accept(this));
  Value *key_ptr = B.CreateBitCast(pop_expr(), B.getInt8PtrTy());

  if (table->type_id()->name_ == "FIXED_MATCH" || table->type_id()->name_ == "INDEXED") {
    TRY2(arg1->accept(this));
    Value *value_ptr = B.CreateBitCast(pop_expr(), B.getInt8PtrTy());

    expr_ = B.CreateCall(update_fn, vector<Value *>({pseudo_map_fd, key_ptr, value_ptr, B.getInt64(BPF_ANY)}));
  } else {
    return mkstatus_(n, "unsupported");
  }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_table_delete(MethodCallExprNode *n) {
  TableDeclStmtNode* table = scopes_->top_table()->lookup(n->id_->name_);
  IdentExprNode* arg0 = static_cast<IdentExprNode*>(n->args_.at(0).get());

  auto table_fd_it = table_fds_.find(table);
  if (table_fd_it == table_fds_.end())
    return mkstatus_(n, "unable to find table %s in table_fds_", n->id_->c_str());
  Function *pseudo_fn = mod_->getFunction("llvm.bpf.pseudo");
  if (!pseudo_fn) return mkstatus_(n, "pseudo fd loader doesn't exist");
  Function *update_fn = mod_->getFunction("bpf_map_update_elem_");
  if (!update_fn) return mkstatus_(n, "bpf_map_update_elem_ undefined");

  CallInst *pseudo_call = B.CreateCall(pseudo_fn, vector<Value *>({B.getInt64(BPF_PSEUDO_MAP_FD),
                                        B.getInt64(table_fd_it->second)}));
  Value *pseudo_map_fd = pseudo_call;

  TRY2(arg0->accept(this));
  Value *key_ptr = B.CreateBitCast(pop_expr(), B.getInt8PtrTy());

  if (table->type_id()->name_ == "FIXED_MATCH" || table->type_id()->name_ == "INDEXED") {
    expr_ = B.CreateCall(update_fn, vector<Value *>({pseudo_map_fd, key_ptr}));
  } else {
    return mkstatus_(n, "unsupported");
  }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_log(MethodCallExprNode *n) {
  vector<Value *> args;
  auto arg = n->args_.begin();
  TRY2((*arg)->accept(this));
  args.push_back(pop_expr());
  args.push_back(B.getInt64(((*arg)->bit_width_ >> 3) + 1));
  ++arg;
  for (; arg != n->args_.end(); ++arg) {
    TRY2((*arg)->accept(this));
    args.push_back(pop_expr());
  }

  // int bpf_trace_printk(fmt, sizeof(fmt), ...)
  FunctionType *printk_fn_type = FunctionType::get(B.getInt32Ty(), vector<Type *>({B.getInt8PtrTy(), B.getInt64Ty()}), true);
  Value *printk_fn = B.CreateIntToPtr(B.getInt64(BPF_FUNC_trace_printk),
                                         PointerType::getUnqual(printk_fn_type));

  expr_ = B.CreateCall(printk_fn, args);
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_packet_rewrite_field(MethodCallExprNode *n) {
  TRY2(n->args_[1]->accept(this));
  TRY2(n->args_[0]->accept(this));
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
  TRY2(lookup_var(n, "skb", scopes_->current_var(), &skb_decl, &skb_mem));
  LoadInst *skb_ptr = B.CreateLoad(skb_mem);
  Value *skb_ptr8 = B.CreateBitCast(skb_ptr, B.getInt8PtrTy());

  expr_ = B.CreateCall(csum_fn, vector<Value *>({skb_ptr8, offset, old_val, new_val, flags}));
  return mkstatus(0);
}

StatusTuple CodegenLLVM::emit_get_usec_time(MethodCallExprNode *n) {
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_method_call_expr_node(MethodCallExprNode *n) {
  if (n->id_->sub_name_.size()) {
    if (n->id_->sub_name_ == "lookup") {
      TRY2(emit_table_lookup(n));
    } else if (n->id_->sub_name_ == "update") {
      TRY2(emit_table_update(n));
    } else if (n->id_->sub_name_ == "delete") {
      TRY2(emit_table_delete(n));
    } else if (n->id_->sub_name_ == "rewrite_field" && n->id_->name_ == "pkt") {
      TRY2(emit_packet_rewrite_field(n));
    }
  } else if (n->id_->name_ == "atomic_add") {
    TRY2(emit_atomic_add(n));
  } else if (n->id_->name_ == "log") {
    TRY2(emit_log(n));
  } else if (n->id_->name_ == "incr_cksum") {
    TRY2(emit_incr_cksum(n));
  } else if (n->id_->name_ == "get_usec_time") {
    TRY2(emit_get_usec_time(n));
  } else {
    return mkstatus_(n, "unsupported");
  }
  TRY2(n->block_->accept(this));
  return mkstatus(0);
}

/* result = lookup(key)
 * if (!result) {
 *   update(key, {0}, BPF_NOEXIST)
 *   result = lookup(key)
 * }
 */
StatusTuple CodegenLLVM::visit_table_index_expr_node(TableIndexExprNode *n) {
  auto table_fd_it = table_fds_.find(n->table_);
  if (table_fd_it == table_fds_.end())
    return mkstatus_(n, "unable to find table %s in table_fds_", n->id_->c_str());

  Function *pseudo_fn = mod_->getFunction("llvm.bpf.pseudo");
  if (!pseudo_fn) return mkstatus_(n, "pseudo fd loader doesn't exist");
  Function *update_fn = mod_->getFunction("bpf_map_update_elem_");
  if (!update_fn) return mkstatus_(n, "bpf_map_update_elem_ undefined");
  Function *lookup_fn = mod_->getFunction("bpf_map_lookup_elem_");
  if (!lookup_fn) return mkstatus_(n, "bpf_map_lookup_elem_ undefined");
  StructType *leaf_type;
  TRY2(lookup_struct_type(n->table_->leaf_type_, &leaf_type));
  PointerType *leaf_ptype = PointerType::getUnqual(leaf_type);

  CallInst *pseudo_call = B.CreateCall(pseudo_fn, vector<Value *>({B.getInt64(BPF_PSEUDO_MAP_FD),
                                        B.getInt64(table_fd_it->second)}));
  Value *pseudo_map_fd = pseudo_call;

  TRY2(n->index_->accept(this));
  Value *key_ptr = B.CreateBitCast(pop_expr(), B.getInt8PtrTy());

  // result = lookup(key)
  Value *lookup1 = B.CreateBitCast(B.CreateCall(lookup_fn, vector<Value *>({pseudo_map_fd, key_ptr})), leaf_ptype);

  Value *result = nullptr;
  if (n->table_->policy_id()->name_ == "AUTO") {
    Function *parent = B.GetInsertBlock()->getParent();
    BasicBlock *label_start = B.GetInsertBlock();
    BasicBlock *label_then = BasicBlock::Create(ctx(), n->id_->name_ + "[].then", parent);
    BasicBlock *label_end = BasicBlock::Create(ctx(), n->id_->name_ + "[].end", parent);

    Value *eq_zero = B.CreateIsNull(lookup1);
    B.CreateCondBr(eq_zero, label_then, label_end);

    B.SetInsertPoint(label_then);
    // var Leaf leaf {0}
    Value *leaf_ptr = B.CreateBitCast(new AllocaInst(leaf_type, "", resolve_entry_stack()), B.getInt8PtrTy());
    B.CreateMemSet(leaf_ptr, B.getInt8(0), B.getInt64(n->table_->leaf_id()->bit_width_ >> 3), 1);
    // update(key, leaf)
    B.CreateCall(update_fn, vector<Value *>({pseudo_map_fd, key_ptr, leaf_ptr, B.getInt64(BPF_NOEXIST)}));

    // result = lookup(key)
    Value *lookup2 = B.CreateBitCast(B.CreateCall(lookup_fn, vector<Value *>({pseudo_map_fd, key_ptr})), leaf_ptype);
    B.CreateBr(label_end);

    B.SetInsertPoint(label_end);

    PHINode *phi = B.CreatePHI(leaf_ptype, 2);
    phi->addIncoming(lookup1, label_start);
    phi->addIncoming(lookup2, label_then);
    result = phi;
  } else if (n->table_->policy_id()->name_ == "NONE") {
    result = lookup1;
  }

  if (n->is_lhs()) {
    if (n->sub_decl_) {
      Type *ptr_type = PointerType::getUnqual(B.getIntNTy(n->sub_decl_->bit_width_));
      // u64 *errval -> uN *errval
      Value *err_cast = B.CreateBitCast(errval_, ptr_type);
      // if valid then &field, else &errval
      Function *parent = B.GetInsertBlock()->getParent();
      BasicBlock *label_start = B.GetInsertBlock();
      BasicBlock *label_then = BasicBlock::Create(ctx(), n->id_->name_ + "[]field.then", parent);
      BasicBlock *label_end = BasicBlock::Create(ctx(), n->id_->name_ + "[]field.end", parent);

      if (1) {
        // the PHI implementation of this doesn't load, maybe eBPF limitation?
        B.CreateCondBr(B.CreateIsNull(result), label_then, label_end);
        B.SetInsertPoint(label_then);
        B.CreateStore(B.getInt32(2), retval_);
        B.CreateBr(resolve_label("DONE"));

        B.SetInsertPoint(label_end);
        vector<Value *> indices({B.getInt32(0), B.getInt32(n->sub_decl_->slot_)});
        expr_ = B.CreateInBoundsGEP(result, indices);
      } else {
        B.CreateCondBr(B.CreateIsNotNull(result), label_then, label_end);

        B.SetInsertPoint(label_then);
        vector<Value *> indices({B.getInt32(0), B.getInt32(n->sub_decl_->slot_)});
        Value *field = B.CreateInBoundsGEP(result, indices);
        B.CreateBr(label_end);

        B.SetInsertPoint(label_end);
        PHINode *phi = B.CreatePHI(ptr_type, 2);
        phi->addIncoming(err_cast, label_start);
        phi->addIncoming(field, label_then);
        expr_ = phi;
      }
    } else {
      return mkstatus_(n, "unsupported");
    }
  } else {
    expr_ = result;
  }
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
  return mkstatus_(n, "unsupported");
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

  StructType *stype;
  StructDeclStmtNode *decl;
  TRY2(lookup_struct_type(n, &stype, &decl));

  Type *ptr_stype = n->is_pointer() ? PointerType::getUnqual(stype) : (PointerType *)stype;
  AllocaInst *ptr_a = new AllocaInst(ptr_stype, "", resolve_entry_stack());
  vars_[n] = ptr_a;

  if (n->struct_id_->scope_name_ == "proto") {
    if (n->is_pointer()) {
      ConstantPointerNull *const_null = ConstantPointerNull::get(cast<PointerType>(ptr_stype));
      B.CreateStore(const_null, ptr_a);
    } else {
      return mkstatus_(n, "unsupported");
      // string var = n->scope_id() + n->id_->name_;
      // /* zero initialize array to be filled in with packet header */
      // emit("uint64_t __%s[%zu] = {}; uint8_t *%s = (uint8_t*)__%s;",
      //      var.c_str(), ((decl->bit_width_ >> 3) + 7) >> 3, var.c_str(), var.c_str());
      // for (auto it = n->init_.begin(); it != n->init_.end(); ++it) {
      //   auto asn = static_cast<AssignExprNode*>(it->get());
      //   if (auto f = decl->field(asn->id_->sub_name_)) {
      //     size_t bit_offset = f->bit_offset_;
      //     size_t bit_width = f->bit_width_;
      //     if (asn->bitop_) {
      //       bit_offset += f->bit_width_ - (asn->bitop_->bit_offset_ + asn->bitop_->bit_width_);
      //       bit_width = std::min(bit_width - asn->bitop_->bit_offset_, asn->bitop_->bit_width_);
      //     }
      //     emit(" bpf_dins(%s + %zu, %zu, %zu, ", var.c_str(), bit_offset >> 3, bit_offset & 0x7, bit_width);
      //     TRY2(asn->rhs_->accept(this));
      //     emit(");");
      //   }
      // }
    }
  } else {
    if (n->is_pointer()) {
      if (n->id_->name_ == "_result") {
        // special case for capturing the return value of a previous method call
        Value *cast_1 = B.CreateBitCast(pop_expr(), ptr_stype);
        B.CreateStore(cast_1, ptr_a);
      } else {
        ConstantPointerNull *const_null = ConstantPointerNull::get(cast<PointerType>(ptr_stype));
        B.CreateStore(const_null, ptr_a);
      }
    } else {
      B.CreateMemSet(ptr_a, B.getInt8(0), B.getInt64(decl->bit_width_ >> 3), 1);
      if (!n->init_.empty()) {
        for (auto it = n->init_.begin(); it != n->init_.end(); ++it)
          TRY2((*it)->accept(this));
      }
    }
  }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_integer_variable_decl_stmt_node(IntegerVariableDeclStmtNode *n) {
  if (!B.GetInsertBlock())
    return mkstatus(0);

  // uintX var = init
  AllocaInst *ptr_a = new AllocaInst(B.getIntNTy(n->bit_width_), n->id_->name_, resolve_entry_stack());
  vars_[n] = ptr_a;

  // todo
  if (!n->init_.empty())
    TRY2(n->init_[0]->accept(this));
  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_struct_decl_stmt_node(StructDeclStmtNode *n) {
  ++indent_;
  StructType *struct_type = StructType::create(ctx(), "_struct." + n->id_->name_);
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

StatusTuple CodegenLLVM::visit_state_decl_stmt_node(StateDeclStmtNode *n) {
  if (!n->id_)
    return mkstatus(0);
  string jump_label = n->scoped_name();
  BasicBlock *label_entry = resolve_label(jump_label);
  B.SetInsertPoint(label_entry);

  auto it = n->subs_.begin();

  scopes_->push_state(it->scope_);

  for (auto in = n->init_.begin(); in != n->init_.end(); ++in)
    TRY2((*in)->accept(this));

  if (n->subs_.size() == 1 && it->id_->name_ == "") {
    // this is not a multistate protocol, emit everything and finish
    TRY2(it->block_->accept(this));
    if (n->parser_) {
      B.CreateBr(resolve_label(jump_label + "_continue"));
      TRY2(n->parser_->accept(this));
    }
  } else {
    return mkstatus_(n, "unsupported");
  }

  scopes_->pop_state();
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

    bpf_map_type map_type = BPF_MAP_TYPE_UNSPEC;
    if (n->type_id()->name_ == "FIXED_MATCH")
      map_type = BPF_MAP_TYPE_HASH;
    else if (n->type_id()->name_ == "INDEXED")
      map_type = BPF_MAP_TYPE_ARRAY;
    else
      return mkstatus_(n, "Table type %s not implemented", n->type_id()->name_.c_str());

    StructType *key_stype, *leaf_stype;
    TRY2(lookup_struct_type(n->key_type_, &key_stype));
    TRY2(lookup_struct_type(n->leaf_type_, &leaf_stype));
    StructType *decl_struct = mod_->getTypeByName("_struct." + n->id_->name_);
    if (!decl_struct)
      decl_struct = StructType::create(ctx(), "_struct." + n->id_->name_);
    if (decl_struct->isOpaque())
      decl_struct->setBody(vector<Type *>({key_stype, leaf_stype}), /*isPacked=*/false);
    GlobalVariable *decl_gvar = new GlobalVariable(*mod_, decl_struct, false,
                                                   GlobalValue::ExternalLinkage, 0, n->id_->name_);
    decl_gvar->setSection("maps");
    tables_[n] = decl_gvar;

    int map_fd = bpf_create_map(map_type, key->bit_width_ / 8, leaf->bit_width_ / 8, n->size_);
    if (map_fd >= 0)
      table_fds_[n] = map_fd;
  } else {
    return mkstatus_(n, "Table %s not implemented", n->table_type_->name_.c_str());
  }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::lookup_struct_type(StructDeclStmtNode *decl, StructType **stype) const {
  auto struct_it = structs_.find(decl);
  if (struct_it == structs_.end())
    return mkstatus_(decl, "could not find IR for type %s", decl->id_->c_str());
  *stype = struct_it->second;

  return mkstatus(0);
}

StatusTuple CodegenLLVM::lookup_struct_type(VariableDeclStmtNode *n, StructType **stype,
                                            StructDeclStmtNode **decl) const {
  if (!n->is_struct())
    return mkstatus_(n, "attempt to search for struct with a non-struct type %s", n->id_->c_str());

  auto var = (StructVariableDeclStmtNode *)n;
  StructDeclStmtNode *type;
  if (var->struct_id_->scope_name_ == "proto")
    type = proto_scopes_->top_struct()->lookup(var->struct_id_->name_, true);
  else
    type = scopes_->top_struct()->lookup(var->struct_id_->name_, true);

  if (!type) return mkstatus_(n, "could not find type %s", var->struct_id_->c_str());

  TRY2(lookup_struct_type(type, stype));

  if (decl)
    *decl = type;

  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit_func_decl_stmt_node(FuncDeclStmtNode *n) {
  if (n->formals_.size() != 1)
    return mkstatus_(n, "Functions must have exactly 1 argument, %zd given", n->formals_.size());

  vector<Type *> formals;
  for (auto it = n->formals_.begin(); it != n->formals_.end(); ++it) {
    VariableDeclStmtNode *formal = it->get();
    if (formal->is_struct()) {
      StructType *stype;
      //TRY2(lookup_struct_type(formal, &stype));
      auto var = (StructVariableDeclStmtNode *)formal;
      stype = mod_->getTypeByName("_struct." + var->struct_id_->name_);
      if (!stype) return mkstatus_(n, "could not find type %s", var->struct_id_->c_str());
      formals.push_back(PointerType::getUnqual(stype));
    } else {
      formals.push_back(B.getIntNTy(formal->bit_width_));
    }
  }
  FunctionType *fn_type = FunctionType::get(B.getInt32Ty(), formals, /*isVarArg=*/false);

  Function *fn = mod_->getFunction(n->id_->name_);
  if (fn) return mkstatus_(n, "Function %s already defined", n->id_->c_str());
  fn = Function::Create(fn_type, GlobalValue::ExternalLinkage, n->id_->name_, mod_);
  fn->setSection(BPF_FN_PREFIX + n->id_->name_);

  BasicBlock *label_entry = BasicBlock::Create(ctx(), "entry", fn);
  B.SetInsertPoint(label_entry);
  string scoped_entry_label = to_string((uintptr_t)fn) + "::entry";
  labels_[scoped_entry_label] = label_entry;
  BasicBlock *label_return = resolve_label("DONE");
  retval_ = new AllocaInst(fn->getReturnType(), "ret", label_entry);
  B.CreateStore(B.getInt32(0), retval_);
  errval_ = new AllocaInst(B.getInt64Ty(), "err", label_entry);
  B.CreateStore(B.getInt64(0), errval_);

  auto formal = n->formals_.begin();
  for (auto arg = fn->arg_begin(); arg != fn->arg_end(); ++arg, ++formal) {
    TRY2((*formal)->accept(this));
    Value *ptr = vars_[formal->get()];
    if (!ptr) return mkstatus_(n, "cannot locate memory location for arg %s", (*formal)->id_->c_str());
    B.CreateStore(&*arg, ptr);

    // Type *ptype;
    // if ((*formal)->is_struct()) {
    //   StructType *type;
    //   TRY2(lookup_struct_type(formal->get(), &type));
    //   ptype = PointerType::getUnqual(type);
    // } else {
    //   ptype = PointerType::getUnqual(B.getIntNTy((*formal)->bit_width_));
    // }

    // arg->setName((*formal)->id_->name_);
    // AllocaInst *ptr = new AllocaInst(ptype, nullptr, (*formal)->id_->name_, label_entry);
    // B.CreateStore(arg, ptr);
    // vars_[formal->get()] = ptr;
  }

  // visit function scoped variables
  {
    scopes_->push_state(n->scope_);

    for (auto it = scopes_->current_var()->obegin(); it != scopes_->current_var()->oend(); ++it)
      TRY2((*it)->accept(this));

    TRY2(n->block_->accept(this));

    scopes_->pop_state();
    if (!B.GetInsertBlock()->getTerminator())
      B.CreateBr(resolve_label("DONE"));

    // always return something
    B.SetInsertPoint(label_return);
    B.CreateRet(B.CreateLoad(retval_));
  }

  return mkstatus(0);
}

StatusTuple CodegenLLVM::visit(Node* root, vector<TableDesc> &tables) {
  scopes_->set_current(scopes_->top_state());
  scopes_->set_current(scopes_->top_var());

  TRY2(print_header());

  for (auto it = scopes_->top_table()->obegin(); it != scopes_->top_table()->oend(); ++it)
    TRY2((*it)->accept(this));

  for (auto it = scopes_->top_func()->obegin(); it != scopes_->top_func()->oend(); ++it)
    TRY2((*it)->accept(this));
  //TRY2(print_parser());

  for (auto table : tables_) {
    bpf_map_type map_type = BPF_MAP_TYPE_UNSPEC;
    if (table.first->type_id()->name_ == "FIXED_MATCH")
      map_type = BPF_MAP_TYPE_HASH;
    else if (table.first->type_id()->name_ == "INDEXED")
      map_type = BPF_MAP_TYPE_ARRAY;
    tables.push_back({
      table.first->id_->name_,
      table_fds_[table.first],
      map_type,
      table.first->key_type_->bit_width_ >> 3,
      table.first->leaf_type_->bit_width_ >> 3,
      table.first->size_,
      "", "",
    });
  }
  return mkstatus(0);
}

StatusTuple CodegenLLVM::print_header() {

  GlobalVariable *gvar_license = new GlobalVariable(*mod_, ArrayType::get(Type::getInt8Ty(ctx()), 4),
                                                    false, GlobalValue::ExternalLinkage, 0, "_license");
  gvar_license->setSection("license");
  gvar_license->setInitializer(ConstantDataArray::getString(ctx(), "GPL", true));

  Function *pseudo_fn = mod_->getFunction("llvm.bpf.pseudo");
  if (!pseudo_fn) {
    pseudo_fn = Function::Create(
        FunctionType::get(B.getInt64Ty(), vector<Type *>({B.getInt64Ty(), B.getInt64Ty()}), false),
        GlobalValue::ExternalLinkage, "llvm.bpf.pseudo", mod_);
  }

  // declare structures
  for (auto it = scopes_->top_struct()->obegin(); it != scopes_->top_struct()->oend(); ++it) {
    if ((*it)->id_->name_ == "_Packet")
      continue;
    TRY2((*it)->accept(this));
  }
  for (auto it = proto_scopes_->top_struct()->obegin(); it != proto_scopes_->top_struct()->oend(); ++it) {
    if ((*it)->id_->name_ == "_Packet")
      continue;
    TRY2((*it)->accept(this));
  }
  return mkstatus(0);
}

int CodegenLLVM::get_table_fd(const string &name) const {
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
  Function *parent = B.GetInsertBlock()->getParent();
  string scoped_label = to_string((uintptr_t)parent) + "::" + label;
  auto it = labels_.find(scoped_label);
  if (it != labels_.end()) return it->second;
  BasicBlock *label_new = BasicBlock::Create(ctx(), label, parent);
  labels_[scoped_label] = label_new;
  return label_new;
}

Instruction * CodegenLLVM::resolve_entry_stack() {
  BasicBlock *label_entry = resolve_label("entry");
  return &label_entry->back();
}

}  // namespace cc
}  // namespace ebpf
