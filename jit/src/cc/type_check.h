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

#include <vector>
#include <string>
#include "cc/node.h"
#include "cc/scope.h"

namespace ebpf {
namespace cc {

class TypeCheck : public Visitor {
 public:
  TypeCheck(Scopes *scopes, Scopes *proto_scopes, const std::map<std::string, std::string>& pragmas)
      : scopes_(scopes), proto_scopes_(proto_scopes), pragmas_(pragmas) {}

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
  const std::map<std::string, std::string> &pragmas_;
};

}  // namespace cc
}  // namespace ebpf
