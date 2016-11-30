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

#include <vector>
#include <bitset>
#include <string>
#include <memory>
#include <algorithm>
#include <stdint.h>

#include "common.h"
#include "bcc_exception.h"
#include "scope.h"

#define REVISION_MASK 0xfff
#define MAJOR_VER_POS 22
#define MAJOR_VER_MASK ~((1 << MAJOR_VER_POS) - 1)
#define MINOR_VER_POS 12
#define MINOR_VER_MASK (~((1 << MINOR_VER_POS) - 1) & (~(MAJOR_VER_MASK)))
#define GET_MAJOR_VER(version) ((version & MAJOR_VER_MASK) >> MAJOR_VER_POS)
#define GET_MINOR_VER(version) ((version & MINOR_VER_MASK) >> MINOR_VER_POS)
#define GET_REVISION(version) (version & REVISION_MASK)
#define MAKE_VERSION(major, minor, rev) \
    ((major << MAJOR_VER_POS) | \
     (minor << MINOR_VER_POS) | \
     (rev & REVISION_MASK))

#define STATUS_RETURN __attribute((warn_unused_result)) StatusTuple

namespace ebpf {

namespace cc {

using std::unique_ptr;
using std::move;
using std::string;
using std::vector;
using std::bitset;
using std::find;

typedef unique_ptr<string> String;

#define NODE_EXPRESSIONS(EXPAND) \
  EXPAND(IdentExprNode, ident_expr_node) \
  EXPAND(AssignExprNode, assign_expr_node) \
  EXPAND(PacketExprNode, packet_expr_node) \
  EXPAND(IntegerExprNode, integer_expr_node) \
  EXPAND(StringExprNode, string_expr_node) \
  EXPAND(BinopExprNode, binop_expr_node) \
  EXPAND(UnopExprNode, unop_expr_node) \
  EXPAND(BitopExprNode, bitop_expr_node) \
  EXPAND(GotoExprNode, goto_expr_node) \
  EXPAND(ReturnExprNode, return_expr_node) \
  EXPAND(MethodCallExprNode, method_call_expr_node) \
  EXPAND(TableIndexExprNode, table_index_expr_node)

#define NODE_STATEMENTS(EXPAND) \
  EXPAND(ExprStmtNode, expr_stmt_node) \
  EXPAND(BlockStmtNode, block_stmt_node) \
  EXPAND(IfStmtNode, if_stmt_node) \
  EXPAND(OnValidStmtNode, onvalid_stmt_node) \
  EXPAND(SwitchStmtNode, switch_stmt_node) \
  EXPAND(CaseStmtNode, case_stmt_node) \
  EXPAND(StructVariableDeclStmtNode, struct_variable_decl_stmt_node) \
  EXPAND(IntegerVariableDeclStmtNode, integer_variable_decl_stmt_node) \
  EXPAND(StructDeclStmtNode, struct_decl_stmt_node) \
  EXPAND(StateDeclStmtNode, state_decl_stmt_node) \
  EXPAND(ParserStateStmtNode, parser_state_stmt_node) \
  EXPAND(MatchDeclStmtNode, match_decl_stmt_node) \
  EXPAND(MissDeclStmtNode, miss_decl_stmt_node) \
  EXPAND(FailureDeclStmtNode, failure_decl_stmt_node) \
  EXPAND(TableDeclStmtNode, table_decl_stmt_node) \
  EXPAND(FuncDeclStmtNode, func_decl_stmt_node)

#define EXPAND_NODES(EXPAND) \
  NODE_EXPRESSIONS(EXPAND) \
  NODE_STATEMENTS(EXPAND)

class Visitor;

// forward declare all classes
#define FORWARD(type, func) class type;
EXPAND_NODES(FORWARD)
#undef FORWARD

#define DECLARE(type) \
  typedef unique_ptr<type> Ptr; \
  virtual StatusTuple accept(Visitor* v);

class Node {
 public:
  typedef unique_ptr<Node> Ptr;
  Node() : line_(-1), column_(-1) {}
  virtual ~Node() {}
  virtual StatusTuple accept(Visitor* v) = 0;
  int line_;
  int column_;
  string text_;
};

template <typename... Args>
StatusTuple mkstatus_(Node *n, const char *fmt, Args... args) {
  StatusTuple status = StatusTuple(n->line_ ? n->line_ : -1, fmt, args...);
  if (n->line_ > 0)
    status.append_msg("\n" + n->text_);
  return status;
}

static inline StatusTuple mkstatus_(Node *n, const char *msg) {
  StatusTuple status = StatusTuple(n->line_ ? n->line_ : -1, msg);
  if (n->line_ > 0)
    status.append_msg("\n" + n->text_);
  return status;
}

class StmtNode : public Node {
 public:
  typedef unique_ptr<StmtNode> Ptr;
  virtual StatusTuple accept(Visitor* v) = 0;

};
typedef vector<StmtNode::Ptr> StmtNodeList;

class ExprNode : public Node {
 public:
  typedef unique_ptr<ExprNode> Ptr;
  virtual StatusTuple accept(Visitor* v) = 0;
  enum expr_type { STRUCT, INTEGER, STRING, VOID, UNKNOWN };
  enum prop_flag { READ = 0, WRITE, PROTO, IS_LHS, IS_REF, IS_PKT, LAST };
  expr_type typeof_;
  StructDeclStmtNode *struct_type_;
  size_t bit_width_;
  bitset<LAST> flags_;
  unique_ptr<BitopExprNode> bitop_;
  ExprNode() : typeof_(UNKNOWN), struct_type_(NULL), flags_(1 << READ) {}
  void copy_type(const ExprNode& other) {
    typeof_ = other.typeof_;
    struct_type_ = other.struct_type_;
    bit_width_ = other.bit_width_;
    flags_ = other.flags_;
  }
  bool is_lhs() const { return flags_[IS_LHS]; }
  bool is_ref() const { return flags_[IS_REF]; }
  bool is_pkt() const { return flags_[IS_PKT]; }
};

typedef vector<ExprNode::Ptr> ExprNodeList;

class IdentExprNode : public ExprNode {
 public:
  DECLARE(IdentExprNode)

  string name_;
  string sub_name_;
  string scope_name_;
  VariableDeclStmtNode *decl_;
  VariableDeclStmtNode *sub_decl_;
  IdentExprNode(const IdentExprNode& other) {
    name_ = other.name_;
    sub_name_ = other.sub_name_;
    scope_name_ = other.scope_name_;
    decl_ = other.decl_;
    sub_decl_ = other.sub_decl_;
  }
  IdentExprNode::Ptr copy() const {
    return IdentExprNode::Ptr(new IdentExprNode(*this));
  }
  explicit IdentExprNode(const string& id) : name_(id) {}
  explicit IdentExprNode(const char* id) : name_(id) {}
  void prepend_scope(const string& id) {
    scope_name_ = id;
  }
  void append_scope(const string& id) {
    scope_name_ = move(name_);
    name_ = id;
  }
  void prepend_dot(const string& id) {
    sub_name_ = move(name_);
    name_ = id;
  }
  void append_dot(const string& id) {
    // we don't support nested struct so keep all subs as single variable
    if (!sub_name_.empty()) {
      sub_name_ += "." + id;
    } else {
      sub_name_ = id;
    }
  }
  const string& full_name() {
    if (full_name_.size()) {
      return full_name_;  // lazy init
    }
    if (scope_name_.size()) {
      full_name_ += scope_name_ + "::";
    }
    full_name_ += name_;
    if (sub_name_.size()) {
      full_name_ += "." + sub_name_;
    }
    return full_name_;
  }
  const char* c_str() const { return name_.c_str(); }
 private:
  string full_name_;
};

class BitopExprNode : public ExprNode {
 public:
  DECLARE(BitopExprNode)

  ExprNode::Ptr expr_;
  size_t bit_offset_;
  size_t bit_width_;
  BitopExprNode(const string& bofs, const string& bsz)
      : bit_offset_(strtoul(bofs.c_str(), NULL, 0)), bit_width_(strtoul(bsz.c_str(), NULL, 0)) {}
};

typedef vector<IdentExprNode::Ptr> IdentExprNodeList;

class AssignExprNode : public ExprNode {
 public:
  DECLARE(AssignExprNode)

  //IdentExprNode *id_;
  ExprNode::Ptr lhs_;
  ExprNode::Ptr rhs_;
  AssignExprNode(IdentExprNode::Ptr id, ExprNode::Ptr rhs)
      : lhs_(move(id)), rhs_(move(rhs)) {
    //id_ = (IdentExprNode *)lhs_.get();
    lhs_->flags_[ExprNode::IS_LHS] = true;
  }
  AssignExprNode(ExprNode::Ptr lhs, ExprNode::Ptr rhs)
      : lhs_(move(lhs)), rhs_(move(rhs)) {
    //id_ = nullptr;
    lhs_->flags_[ExprNode::IS_LHS] = true;
  }
};

class PacketExprNode : public ExprNode {
 public:
  DECLARE(PacketExprNode)

  IdentExprNode::Ptr id_;
  explicit PacketExprNode(IdentExprNode::Ptr id) : id_(move(id)) {}
};

class StringExprNode : public ExprNode {
 public:
  DECLARE(StringExprNode)

  string val_;
  explicit StringExprNode(string *val) : val_(move(*val)) {
    delete val;
  }
  explicit StringExprNode(const string &val) : val_(val) {}
};

class IntegerExprNode : public ExprNode {
 public:
  DECLARE(IntegerExprNode)

  size_t bits_;
  string val_;
  IntegerExprNode(string* val, string* bits)
      : bits_(strtoul(bits->c_str(), NULL, 0)), val_(move(*val)) {
    delete val;
    delete bits;
  }
  explicit IntegerExprNode(string* val)
      : bits_(0), val_(move(*val)) {
    delete val;
  }
  explicit IntegerExprNode(const string& val) : bits_(0), val_(val) {}
  explicit IntegerExprNode(const string& val, size_t bits) : bits_(bits), val_(val) {}
};

class BinopExprNode : public ExprNode {
 public:
  DECLARE(BinopExprNode)

  ExprNode::Ptr lhs_;
  int op_;
  ExprNode::Ptr rhs_;
  BinopExprNode(ExprNode::Ptr lhs, int op, ExprNode::Ptr rhs)
      : lhs_(move(lhs)), op_(op), rhs_(move(rhs))
  {}
};

class UnopExprNode : public ExprNode {
 public:
  DECLARE(UnopExprNode)

  ExprNode::Ptr expr_;
  int op_;
  UnopExprNode(int op, ExprNode::Ptr expr) : expr_(move(expr)), op_(op) {}
};

class GotoExprNode : public ExprNode {
 public:
  DECLARE(GotoExprNode)

  bool is_continue_;
  IdentExprNode::Ptr id_;
  GotoExprNode(IdentExprNode::Ptr id, bool is_continue = false)
      : is_continue_(is_continue), id_(move(id)) {}
};

class ReturnExprNode : public ExprNode {
 public:
  DECLARE(ReturnExprNode)

  ExprNode::Ptr expr_;
  ReturnExprNode(ExprNode::Ptr expr)
      : expr_(move(expr)) {}
};

class BlockStmtNode : public StmtNode {
 public:
  DECLARE(BlockStmtNode)

  explicit BlockStmtNode(StmtNodeList stmts = StmtNodeList())
    : stmts_(move(stmts)), scope_(NULL) {}
  ~BlockStmtNode() { delete scope_; }
  StmtNodeList stmts_;
  Scopes::VarScope* scope_;
};

class MethodCallExprNode : public ExprNode {
 public:
  DECLARE(MethodCallExprNode)

  IdentExprNode::Ptr id_;
  ExprNodeList args_;
  BlockStmtNode::Ptr block_;
  MethodCallExprNode(IdentExprNode::Ptr id, ExprNodeList&& args, int lineno)
      : id_(move(id)), args_(move(args)), block_(make_unique<BlockStmtNode>()) {
    line_ = lineno;
  }
};

class TableIndexExprNode : public ExprNode {
 public:
  DECLARE(TableIndexExprNode)

  IdentExprNode::Ptr id_;
  IdentExprNode::Ptr sub_;
  ExprNode::Ptr index_;
  TableDeclStmtNode *table_;
  VariableDeclStmtNode *sub_decl_;
  TableIndexExprNode(IdentExprNode::Ptr id, ExprNode::Ptr index)
      : id_(move(id)), index_(move(index)), table_(nullptr), sub_decl_(nullptr)
  {}
};

class ExprStmtNode : public StmtNode {
 public:
  DECLARE(ExprStmtNode)

  ExprNode::Ptr expr_;
  explicit ExprStmtNode(ExprNode::Ptr expr) : expr_(move(expr)) {}
};

class IfStmtNode : public StmtNode {
 public:
  DECLARE(IfStmtNode)

  ExprNode::Ptr cond_;
  StmtNode::Ptr true_block_;
  StmtNode::Ptr false_block_;
  // create an if () {} expression
  IfStmtNode(ExprNode::Ptr cond, StmtNode::Ptr true_block)
      : cond_(move(cond)), true_block_(move(true_block)) {}
  // create an if () {} else {} expression
  IfStmtNode(ExprNode::Ptr cond, StmtNode::Ptr true_block, StmtNode::Ptr false_block)
      : cond_(move(cond)), true_block_(move(true_block)),
      false_block_(move(false_block)) {}
};

class OnValidStmtNode : public StmtNode {
 public:
  DECLARE(OnValidStmtNode)

  IdentExprNode::Ptr cond_;
  StmtNode::Ptr block_;
  StmtNode::Ptr else_block_;
  // create an onvalid () {} expression
  OnValidStmtNode(IdentExprNode::Ptr cond, StmtNode::Ptr block)
      : cond_(move(cond)), block_(move(block)) {}
  // create an onvalid () {} else {} expression
  OnValidStmtNode(IdentExprNode::Ptr cond, StmtNode::Ptr block, StmtNode::Ptr else_block)
      : cond_(move(cond)), block_(move(block)),
      else_block_(move(else_block)) {}
};

class SwitchStmtNode : public StmtNode {
 public:
  DECLARE(SwitchStmtNode)
  ExprNode::Ptr cond_;
  BlockStmtNode::Ptr block_;
  SwitchStmtNode(ExprNode::Ptr cond, BlockStmtNode::Ptr block)
      : cond_(move(cond)), block_(move(block)) {}
};

class CaseStmtNode : public StmtNode {
 public:
  DECLARE(CaseStmtNode)
  IntegerExprNode::Ptr value_;
  BlockStmtNode::Ptr block_;
  CaseStmtNode(IntegerExprNode::Ptr value, BlockStmtNode::Ptr block)
      : value_(move(value)), block_(move(block)) {}
  explicit CaseStmtNode(BlockStmtNode::Ptr block) : block_(move(block)) {}
};

class VariableDeclStmtNode : public StmtNode {
 public:
  typedef unique_ptr<VariableDeclStmtNode> Ptr;
  virtual StatusTuple accept(Visitor* v) = 0;
  enum storage_type { INTEGER, STRUCT, STRUCT_REFERENCE };

  IdentExprNode::Ptr id_;
  ExprNodeList init_;
  enum storage_type storage_type_;
  size_t bit_width_;
  size_t bit_offset_;
  int slot_;
  string scope_id_;
  explicit VariableDeclStmtNode(IdentExprNode::Ptr id, storage_type t, size_t bit_width = 0, size_t bit_offset = 0)
      : id_(move(id)), storage_type_(t), bit_width_(bit_width), bit_offset_(bit_offset), slot_(0) {}
  const char* scope_id() const { return scope_id_.c_str(); }
  bool is_struct() { return (storage_type_ == STRUCT || storage_type_ == STRUCT_REFERENCE); }
  bool is_pointer() { return (storage_type_ == STRUCT_REFERENCE); }
};

typedef vector<VariableDeclStmtNode::Ptr> FormalList;

class StructVariableDeclStmtNode : public VariableDeclStmtNode {
 public:
  DECLARE(StructVariableDeclStmtNode)

  IdentExprNode::Ptr struct_id_;
  StructVariableDeclStmtNode(IdentExprNode::Ptr struct_id, IdentExprNode::Ptr id,
                             VariableDeclStmtNode::storage_type t = VariableDeclStmtNode::STRUCT)
      : VariableDeclStmtNode(move(id), t), struct_id_(move(struct_id)) {}
};

class IntegerVariableDeclStmtNode : public VariableDeclStmtNode {
 public:
  DECLARE(IntegerVariableDeclStmtNode)

  IntegerVariableDeclStmtNode(IdentExprNode::Ptr id, const string& bits)
      : VariableDeclStmtNode(move(id), VariableDeclStmtNode::INTEGER, strtoul(bits.c_str(), NULL, 0)) {}
};

class StructDeclStmtNode : public StmtNode {
 public:
  DECLARE(StructDeclStmtNode)

  IdentExprNode::Ptr id_;
  FormalList stmts_;
  size_t bit_width_;
  bool packed_;
  StructDeclStmtNode(IdentExprNode::Ptr id, FormalList&& stmts = FormalList())
      : id_(move(id)), stmts_(move(stmts)), bit_width_(0), packed_(false) {}
  VariableDeclStmtNode* field(const string& name) const;
  int indexof(const string& name) const;
  bool is_packed() const { return packed_; }
};

class ParserStateStmtNode : public StmtNode {
 public:
  DECLARE(ParserStateStmtNode)

  IdentExprNode::Ptr id_;
  StmtNode* next_state_;
  string scope_id_;
  explicit ParserStateStmtNode(IdentExprNode::Ptr id)
      : id_(move(id)) {}
  static Ptr make(const IdentExprNode::Ptr& id) {
    return Ptr(new ParserStateStmtNode(id->copy()));
  }
  string scoped_name() const { return scope_id_ + id_->name_; }
};

class StateDeclStmtNode : public StmtNode {
 public:
  DECLARE(StateDeclStmtNode)

  struct Sub {
    IdentExprNode::Ptr id_;
    BlockStmtNode::Ptr block_;
    ParserStateStmtNode::Ptr parser_;
    Scopes::StateScope* scope_;
    Sub(decltype(id_) id, decltype(block_) block, decltype(parser_) parser, decltype(scope_) scope)
        : id_(move(id)), block_(move(block)), parser_(move(parser)), scope_(scope) {}
    ~Sub() { delete scope_; }
    Sub(Sub&& other) : scope_(NULL) {
      *this = move(other);
    }
    Sub& operator=(Sub&& other) {
      if (this == &other) {
        return *this;
      }
      id_ = move(other.id_);
      block_ = move(other.block_);
      parser_ = move(other.parser_);
      std::swap(scope_, other.scope_);
      return *this;
    }
  };

  IdentExprNode::Ptr id_;
  StmtNodeList init_;
  string scope_id_;
  ParserStateStmtNode::Ptr parser_;
  vector<Sub> subs_;
  StateDeclStmtNode() {}
  StateDeclStmtNode(IdentExprNode::Ptr id, BlockStmtNode::Ptr block) : id_(move(id)) {
    subs_.push_back(Sub(make_unique<IdentExprNode>(""), move(block), ParserStateStmtNode::Ptr(), NULL));
  }
  StateDeclStmtNode(IdentExprNode::Ptr id1, IdentExprNode::Ptr id2, BlockStmtNode::Ptr block)
      : id_(move(id1)) {
    subs_.push_back(Sub(move(id2), move(block), ParserStateStmtNode::Ptr(), NULL));
  }
  string scoped_name() const { return scope_id_ + id_->name_; }
  vector<Sub>::iterator find_sub(const string& id) {
    return find_if(subs_.begin(), subs_.end(), [&id] (const Sub& sub) {
      if (sub.id_->name_ == id)
        return true;
      return false;
    });

  }
};

class MatchDeclStmtNode : public StmtNode {
 public:
  DECLARE(MatchDeclStmtNode)

  IdentExprNode::Ptr id_;
  FormalList formals_;
  BlockStmtNode::Ptr block_;
  MatchDeclStmtNode(IdentExprNode::Ptr id, FormalList&& formals, BlockStmtNode::Ptr block)
      : id_(move(id)), formals_(move(formals)), block_(move(block)) {}
};

class MissDeclStmtNode : public StmtNode {
 public:
  DECLARE(MissDeclStmtNode)

  IdentExprNode::Ptr id_;
  FormalList formals_;
  BlockStmtNode::Ptr block_;
  MissDeclStmtNode(IdentExprNode::Ptr id, FormalList&& formals, BlockStmtNode::Ptr block)
      : id_(move(id)), formals_(move(formals)), block_(move(block)) {}
};

class FailureDeclStmtNode : public StmtNode {
 public:
  DECLARE(FailureDeclStmtNode)

  IdentExprNode::Ptr id_;
  FormalList formals_;
  BlockStmtNode::Ptr block_;
  FailureDeclStmtNode(IdentExprNode::Ptr id, FormalList&& formals, BlockStmtNode::Ptr block)
      : id_(move(id)), formals_(move(formals)), block_(move(block)) {}
};

class TableDeclStmtNode : public StmtNode {
 public:
  DECLARE(TableDeclStmtNode)

  IdentExprNode::Ptr table_type_;
  IdentExprNodeList templates_;
  IdentExprNode::Ptr id_;
  StructDeclStmtNode *key_type_;
  StructDeclStmtNode *leaf_type_;
  IdentExprNode * key_id() { return templates_.at(0).get(); }
  IdentExprNode * leaf_id() { return templates_.at(1).get(); }
  IdentExprNode * type_id() { return templates_.at(2).get(); }
  IdentExprNode * policy_id() { return templates_.at(3).get(); }
  size_t size_;
  TableDeclStmtNode(IdentExprNode::Ptr table_type, IdentExprNodeList&& templates,
                    IdentExprNode::Ptr id, string* size)
      : table_type_(move(table_type)), templates_(move(templates)), id_(move(id)),
      key_type_(nullptr), leaf_type_(nullptr), size_(strtoul(size->c_str(), NULL, 0)) {
    delete size;
  }
};

class FuncDeclStmtNode : public StmtNode {
 public:
  DECLARE(FuncDeclStmtNode)

  IdentExprNode::Ptr id_;
  FormalList formals_;
  BlockStmtNode::Ptr block_;
  Scopes::StateScope* scope_;
  FuncDeclStmtNode(IdentExprNode::Ptr id, FormalList&& formals, BlockStmtNode::Ptr block)
      : id_(move(id)), formals_(move(formals)), block_(move(block)), scope_(NULL) {}
};

class Visitor {
 public:
  typedef StatusTuple Ret;
  virtual ~Visitor() {}
#define VISIT(type, func) virtual STATUS_RETURN visit_##func(type* n) = 0;
  EXPAND_NODES(VISIT)
#undef VISIT
};

#undef DECLARE

}  // namespace cc
}  // namespace ebpf
