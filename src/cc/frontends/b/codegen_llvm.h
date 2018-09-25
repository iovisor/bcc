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

#include <map>
#include <stdio.h>
#include <vector>
#include <string>
#include <set>

#include "node.h"
#include "scope.h"

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
class Type;
class Value;
class GlobalVariable;
}

namespace ebpf {

class TableStorage;

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

  STATUS_RETURN visit(Node *n, TableStorage &ts, const std::string &id,
                      const std::string &maps_ns);

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
  llvm::AllocaInst *make_alloca(llvm::Instruction *Inst, llvm::Type *Ty,
                                const std::string &name = "",
                                llvm::Value *ArraySize = nullptr);
  llvm::AllocaInst *make_alloca(llvm::BasicBlock *BB, llvm::Type *Ty,
                                const std::string &name = "",
                                llvm::Value *ArraySize = nullptr);
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
