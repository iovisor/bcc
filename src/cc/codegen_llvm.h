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

#pragma once

#include <stdio.h>
#include <vector>
#include <string>
#include <set>

#include "cc/node.h"
#include "cc/scope.h"

namespace llvm {
class AllocaInst;
class BasicBlock;
class BranchInst;
class Constant;
class Instruction;
class IRBuilderBase;
class LLVMContext;
class Module;
class StructType;
class SwitchInst;
}

namespace ebpf {
namespace cc {

class BlockStack;
class SwitchStack;

using std::vector;
using std::string;
using std::set;

class CodegenLLVM : public Visitor {
  friend class BlockStack;
  friend class SwitchStack;
 public:
  CodegenLLVM(llvm::Module *mod, Scopes *scopes, Scopes *proto_scopes);
  virtual ~CodegenLLVM();

#define VISIT(type, func) virtual STATUS_RETURN visit_##func(type* n);
  EXPAND_NODES(VISIT)
#undef VISIT

  virtual STATUS_RETURN visit(Node* n);

  int get_table_fd(const std::string &name) const;

 private:
  STATUS_RETURN emit_short_circuit_and(BinopExprNode* n);
  STATUS_RETURN emit_short_circuit_or(BinopExprNode* n);
  STATUS_RETURN emit_table_lookup(MethodCallExprNode* n);
  STATUS_RETURN emit_table_update(MethodCallExprNode* n);
  STATUS_RETURN emit_table_delete(MethodCallExprNode* n);
  STATUS_RETURN emit_log(MethodCallExprNode* n);
  STATUS_RETURN emit_packet_rewrite_field(MethodCallExprNode* n);
  STATUS_RETURN emit_atomic_add(MethodCallExprNode* n);
  STATUS_RETURN emit_cksum(MethodCallExprNode* n);
  STATUS_RETURN emit_incr_cksum(MethodCallExprNode* n, size_t sz = 0);
  STATUS_RETURN emit_lb_hash(MethodCallExprNode* n);
  STATUS_RETURN emit_sizeof(MethodCallExprNode* n);
  STATUS_RETURN emit_get_usec_time(MethodCallExprNode* n);
  STATUS_RETURN emit_forward_to_vnf(MethodCallExprNode* n);
  STATUS_RETURN emit_forward_to_group(MethodCallExprNode* n);
  STATUS_RETURN print_header();

  llvm::LLVMContext & ctx() const;
  llvm::Constant * const_int(uint64_t val, unsigned bits = 64, bool is_signed = false);
  llvm::Value * pop_expr();
  llvm::BasicBlock * resolve_label(const string &label);
  llvm::Instruction * resolve_entry_stack();
  StatusTuple lookup_var(Node *n, const std::string &name, Scopes::VarScope *scope,
                         VariableDeclStmtNode **decl, llvm::Value **mem) const;
  StatusTuple lookup_struct_type(StructDeclStmtNode *decl, llvm::StructType **stype) const;
  StatusTuple lookup_struct_type(VariableDeclStmtNode *n, llvm::StructType **stype,
                                 StructDeclStmtNode **decl = nullptr) const;

  template <typename... Args> void emit(const char *fmt, Args&&... params);
  void emit(const char *s);

  FILE* out_;
  llvm::Module* mod_;
  llvm::IRBuilderBase *b_;
  int indent_;
  int tmp_reg_index_;
  Scopes *scopes_;
  Scopes *proto_scopes_;
  vector<vector<string> > free_instructions_;
  vector<string> table_inits_;
  map<string, string> proto_rewrites_;
  map<TableDeclStmtNode *, llvm::GlobalVariable *> tables_;
  map<TableDeclStmtNode *, int> table_fds_;
  map<VariableDeclStmtNode *, llvm::Value *> vars_;
  map<StructDeclStmtNode *, llvm::StructType *> structs_;
  map<string, llvm::BasicBlock *> labels_;
  llvm::SwitchInst *cur_switch_;
  llvm::Value *expr_;
  llvm::AllocaInst *retval_;
  llvm::AllocaInst *errval_;
};

}  // namespace cc
}  // namespace ebpf
