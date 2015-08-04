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

#include <stdio.h>
#include <vector>
#include <string>

#include "node.h"

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
