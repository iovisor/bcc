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

#include <stdio.h>

#include "node.h"

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
