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

#include "bpf_module.h"

namespace ebpf {

using namespace llvm;

// Constructor/destructor needs LLVM classes to be defined. Since we have multiple
// definitions of LLVM classes (dummy and llvm) this file is included after LLVM
// classes are defined. This avoids duplication of these functions.

BPFModule::BPFModule(unsigned flags, TableStorage *ts, bool rw_engine_enabled,
    const std::string &maps_ns)
    : flags_(flags),
      rw_engine_enabled_(rw_engine_enabled),
      used_b_loader_(false),
      ctx_(new LLVMContext),
      id_(std::to_string((uintptr_t)this)),
      maps_ns_(maps_ns),
      ts_(ts) {
  init_module();
  init_clang();
}

BPFModule::~BPFModule() {
  cleanup_clang();
  cleanup_module();
}

}  // namespace ebpf
