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

#include <stdio.h>
#include <vector>
#include <string>

#include "cc/node.h"

namespace ebpf {
namespace cc {

#define ACCEPT(type, func) \
  STATUS_RETURN type::accept(Visitor* v) { return v->visit_##func(this); }
EXPAND_NODES(ACCEPT)
#undef ACCEPT

VariableDeclStmtNode* StructDeclStmtNode::field(const string& name) const {
  for (auto it = stmts_.begin(); it != stmts_.end(); ++it) {
    if ((*it)->id_->name_ == name) {
      return it->get();
    }
  }
  return NULL;
}

int StructDeclStmtNode::indexof(const string& name) const {
  int i = 0;
  for (auto it = stmts_.begin(); it != stmts_.end(); ++it, ++i) {
    if ((*it)->id_->name_ == name) {
      return i;
    }
  }
  return -1;
}

}  // namespace cc
}  // namespace ebpf
