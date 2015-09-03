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
#include <string>
#include "node.h"
#include "scope.h"

namespace ebpf {
namespace cc {

class TypeCheck : public Visitor {
 public:
  TypeCheck(Scopes *scopes, Scopes *proto_scopes)
      : scopes_(scopes), proto_scopes_(proto_scopes) {}

  virtual STATUS_RETURN visit(Node* n);
  STATUS_RETURN expect_method_arg(MethodCallExprNode* n, size_t num, size_t num_def_args);
  STATUS_RETURN check_lookup_method(MethodCallExprNode* n);
  STATUS_RETURN check_update_method(MethodCallExprNode* n);
  STATUS_RETURN check_delete_method(MethodCallExprNode* n);

#define VISIT(type, func) virtual STATUS_RETURN visit_##func(type* n);
  EXPAND_NODES(VISIT)
#undef VISIT

 private:
  Scopes *scopes_;
  Scopes *proto_scopes_;
  vector<string> errors_;
};

}  // namespace cc
}  // namespace ebpf
