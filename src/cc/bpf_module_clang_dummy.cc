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
#include "table_storage.h"
#include "func_source.h"


// Dummy classes to make unique_ptr happy
namespace llvm {

class LLVMContext {};
class ExecutionEngine {};
class Module {};

}

// Constructor/destructor
#include "bpf_module_constructor_destructor.h"

namespace ebpf {

using std::string;

void BPFModule::init_clang() {
}

void BPFModule::cleanup_clang() {
}

// load a B file, which comes in two parts
int BPFModule::load_b(const string &filename, const string &proto_filename) {
  return -1;
}

// load a C file
int BPFModule::load_c(const string &filename, const char *cflags[], int ncflags) {
  return -1;
}

// load a C text string
int BPFModule::load_string(const string &text, const char *cflags[], int ncflags) {
  return -1;
}

} // namespace ebpf
