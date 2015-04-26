/*
 * ====================================================================
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
 * ====================================================================
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
class TimerDeclStmtNode;
class VariableDeclStmtNode;
class TableDeclStmtNode;
class StructDeclStmtNode;

template <typename T>
class Scope {
 public:
  Scope() {}
  Scope(Scope<T>* scope, int id) : parent_(scope), id_(id) {}
  enum search_type { LOCAL, GLOBAL };

  T* lookup(const string& name, bool search_local = true) {
    auto it = elems_.find(name);
    if (it != elems_.end()) {
      return it->second;
    }

    if (search_local || !parent_) {
      return NULL;
    }
    return parent_->lookup(name, search_local);
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
  typedef Scope<TimerDeclStmtNode> TimerScope;
  typedef Scope<VariableDeclStmtNode> VarScope;
  typedef Scope<TableDeclStmtNode> TableScope;

  Scopes() : var_id__(0), state_id_(0), var_id_(0),
    current_var_scope_(NULL), top_var_scope_(NULL),
    current_state_scope_(NULL), top_state_scope_(NULL),
    top_timer_scope_(new TimerScope(NULL, 1)),
    top_struct_scope_(new StructScope(NULL, 1)),
    top_table_scope_(new TableScope(NULL, 1)) {}
  ~Scopes() {
    delete top_timer_scope_;
    delete top_struct_scope_;
    delete top_table_scope_;
    delete top_state_scope_;
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
  VarScope* current_var() { return current_var_scope_; }
  VarScope* top_var() { return top_var_scope_; }

  void set_current(StateScope* s) { current_state_scope_ = s; }
  StateScope* current_state() { return current_state_scope_; }
  StateScope* top_state() { return top_state_scope_; }

  TimerScope* top_timer() { return top_timer_scope_; }

  StructScope* top_struct() { return top_struct_scope_; }

  TableScope* top_table() { return top_table_scope_; }

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
  TimerScope* top_timer_scope_;
  StructScope* top_struct_scope_;
  TableScope* top_table_scope_;
};

}  // namespace cc
}  // namespace ebpf
