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

#include <stdio.h>

#include "cc/node.h"

namespace ebpf {
namespace cc {

class Printer : public Visitor {
 public:
  explicit Printer(FILE* out) : out_(out), indent_(0) {}

  void print_indent();

#define VISIT(type, func) virtual STATUS_RETURN visit_##func(type* n);
  EXPAND_NODES(VISIT)
#undef VISIT

 private:
  FILE* out_;
  int indent_;
};

}  // namespace cc
}  // namespace ebpf
