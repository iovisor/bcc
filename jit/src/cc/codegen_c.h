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

namespace ebpf {
namespace cc {

using std::vector;
using std::string;
using std::set;

class CodegenC : public Visitor {
 public:
  CodegenC(FILE* out, Scopes::Ptr scopes, Scopes::Ptr proto_scopes, bool use_pre_header)
      : out_(out), indent_(0), tmp_reg_index_(0), scopes_(scopes),
      proto_scopes_(proto_scopes), use_pre_header_(use_pre_header) {}

#define VISIT(type, func) virtual void visit_##func(type* n);
  EXPAND_NODES(VISIT)
#undef VISIT

  virtual int visit(Node* n);

  void emit_table_lookup(MethodCallExprNode* n);
  void emit_table_update(MethodCallExprNode* n);
  void emit_table_delete(MethodCallExprNode* n);
  void emit_channel_push(MethodCallExprNode* n);
  void emit_channel_push_generic(MethodCallExprNode* n);
  void emit_log(MethodCallExprNode* n);
  void emit_packet_forward(MethodCallExprNode* n);
  void emit_packet_replicate(MethodCallExprNode* n);
  void emit_packet_clone_forward(MethodCallExprNode* n);
  void emit_packet_forward_self(MethodCallExprNode* n);
  void emit_packet_drop(MethodCallExprNode* n);
  void emit_packet_broadcast(MethodCallExprNode* n);
  void emit_packet_multicast(MethodCallExprNode* n);
  void emit_packet_push_header(MethodCallExprNode* n);
  void emit_packet_pop_header(MethodCallExprNode* n);
  void emit_packet_push_vlan(MethodCallExprNode* n);
  void emit_packet_pop_vlan(MethodCallExprNode* n);
  void emit_packet_rewrite_field(MethodCallExprNode* n);
  void emit_atomic_add(MethodCallExprNode* n);
  void emit_cksum(MethodCallExprNode* n);
  void emit_incr_cksum_u16(MethodCallExprNode* n);
  void emit_incr_cksum_u32(MethodCallExprNode* n);
  void emit_lb_hash(MethodCallExprNode* n);
  void emit_sizeof(MethodCallExprNode* n);
  void emit_get_usec_time(MethodCallExprNode* n);
  void emit_forward_to_vnf(MethodCallExprNode* n);
  void emit_forward_to_group(MethodCallExprNode* n);
  void print_parser();
  void print_timer();
  void print_header();
  void print_footer();

 private:
  void indent();

  template <typename... Args> void emitln(const char *fmt, Args&&... params);
  template <typename... Args> void lnemit(const char *fmt, Args&&... params);
  template <typename... Args> void emit(const char *fmt, Args&&... params);
  void emitln(const char *s);
  void lnemit(const char *s);
  void emit(const char *s);
  void emit_comment(Node* n);

  FILE* out_;
  int indent_;
  int tmp_reg_index_;
  Scopes::Ptr scopes_;
  Scopes::Ptr proto_scopes_;
  bool use_pre_header_;
  vector<vector<string> > free_instructions_;
  vector<string> table_inits_;
  map<string, string> proto_rewrites_;
};

}  // namespace cc
}  // namespace ebpf
