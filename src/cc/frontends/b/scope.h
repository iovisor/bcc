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
#include <string>
#include <vector>
#include <memory>

namespace ebpf {
namespace cc {

using std::string;
using std::vector;
using std::map;
using std::pair;
using std::unique_ptr;

class StateDeclStmtNode;
class VariableDeclStmtNode;
class TableDeclStmtNode;
class StructDeclStmtNode;
class FuncDeclStmtNode;

enum search_type { SCOPE_LOCAL, SCOPE_GLOBAL };

template <typename T>
class Scope {
 public:
  Scope() {}
  Scope(Scope<T>* scope, int id) : parent_(scope), id_(id) {}

  T* lookup(const string &name, bool search_local = true) {
    return lookup(name, search_local ? SCOPE_LOCAL : SCOPE_GLOBAL);
  }
  T * lookup(const string &name, search_type stype) {
    auto it = elems_.find(name);
    if (it != elems_.end())
      return it->second;

    if (stype == SCOPE_LOCAL || !parent_)
      return nullptr;
    return parent_->lookup(name, stype);
  }
  void add(const string& name, T* n) {
    elems_[name] = n;
    elems_ordered_.push_back(n);
  }
  typename map<string, T*>::iterator begin() { return elems_.begin(); }
  typename map<string, T*>::iterator end() { return elems_.end(); }
  typename vector<T*>::iterator obegin() { return elems_ordered_.begin(); }
  typename vector<T*>::iterator oend() { return elems_ordered_.end(); }

  Scope<T> *parent_;
  int id_;
  map<string, T*> elems_;
  vector<T*> elems_ordered_;
};

/**
 * Hold the current stack of scope pointers.  Lookups search upwards.
 * Actual scope pointers are kept in the AST.
 */
class Scopes {
 public:
  typedef unique_ptr<Scopes> Ptr;
  typedef Scope<StructDeclStmtNode> StructScope;
  typedef Scope<StateDeclStmtNode> StateScope;
  typedef Scope<VariableDeclStmtNode> VarScope;
  typedef Scope<TableDeclStmtNode> TableScope;
  typedef Scope<FuncDeclStmtNode> FuncScope;

  Scopes() : var_id__(0), state_id_(0), var_id_(0),
    current_var_scope_(nullptr), top_var_scope_(nullptr),
    current_state_scope_(nullptr), top_state_scope_(nullptr),
    top_struct_scope_(new StructScope(nullptr, 1)),
    top_table_scope_(new TableScope(nullptr, 1)),
    top_func_scope_(new FuncScope(nullptr, 1)) {}
  ~Scopes() {
    delete top_func_scope_;
    delete top_struct_scope_;
    delete top_table_scope_;
    delete top_state_scope_;
  }

  void push_var(VarScope *scope) {
    if (scope == top_var_scope_)
      return;
    scope->parent_ = current_var_scope_;
    current_var_scope_ = scope;
  }
  void pop_var() {
    if (current_var_scope_ == top_var_scope_)
      return;
    VarScope *old = current_var_scope_;
    current_var_scope_ = old->parent_;
    old->parent_ = nullptr;
  }

  void push_state(StateScope *scope) {
    if (scope == top_state_scope_)
      return;
    scope->parent_ = current_state_scope_;
    current_state_scope_ = scope;
  }
  void pop_state() {
    if (current_state_scope_ == top_state_scope_)
      return;
    StateScope *old = current_state_scope_;
    current_state_scope_ = old->parent_;
    old->parent_ = nullptr;
  }

  /// While building the AST, allocate a new scope
  VarScope* enter_var_scope() {
    current_var_scope_ = new VarScope(current_var_scope_, next_var_id());
    if (!top_var_scope_) {
      top_var_scope_ = current_var_scope_;
    }
    return current_var_scope_;
  }

  VarScope* exit_var_scope() {
    current_var_scope_ = current_var_scope_->parent_;
    return current_var_scope_;
  }

  StateScope* enter_state_scope() {
    current_state_scope_ = new StateScope(current_state_scope_, next_state_id());
    if (!top_state_scope_) {
      top_state_scope_ = current_state_scope_;
    }
    return current_state_scope_;
  }

  StateScope* exit_state_scope() {
    current_state_scope_ = current_state_scope_->parent_;
    return current_state_scope_;
  }

  void set_current(VarScope* s) { current_var_scope_ = s; }
  VarScope* current_var() const { return current_var_scope_; }
  VarScope* top_var() const { return top_var_scope_; }

  void set_current(StateScope* s) { current_state_scope_ = s; }
  StateScope* current_state() const { return current_state_scope_; }
  StateScope* top_state() const { return top_state_scope_; }

  StructScope* top_struct() const { return top_struct_scope_; }

  TableScope* top_table() const { return top_table_scope_; }
  FuncScope* top_func() const { return top_func_scope_; }

  int next_id() { return ++var_id__; }
  int next_state_id() { return ++state_id_; }
  int next_var_id() { return ++var_id_; }

  int var_id__;
  int state_id_;
  int var_id_;
  VarScope* current_var_scope_;
  VarScope* top_var_scope_;
  StateScope* current_state_scope_;
  StateScope* top_state_scope_;
  StructScope* top_struct_scope_;
  TableScope* top_table_scope_;
  FuncScope* top_func_scope_;
};

}  // namespace cc
}  // namespace ebpf
