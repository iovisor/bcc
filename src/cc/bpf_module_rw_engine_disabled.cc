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

#include "bpf_module.h"

namespace ebpf {

bool bpf_module_rw_engine_enabled(void) {
  return false;
}

void BPFModule::initialize_rw_engine() {
}

void BPFModule::cleanup_rw_engine() {
}

int BPFModule::annotate() {
  return -1;
}

} // namespace ebpf
