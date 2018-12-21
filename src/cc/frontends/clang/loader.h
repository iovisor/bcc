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

#include <map>
#include <memory>
#include <string>

#include "table_storage.h"
#include "func_source.h"

namespace llvm {
class Module;
class LLVMContext;
class MemoryBuffer;
}

namespace ebpf {

class ClangLoader {
 public:
  explicit ClangLoader(llvm::LLVMContext *ctx, unsigned flags);
  ~ClangLoader();
  int parse(std::unique_ptr<llvm::Module> *mod, TableStorage &ts,
            const std::string &file, bool in_memory, const char *cflags[],
            int ncflags, const std::string &id, FuncSource &func_src,
            std::string &mod_src, const std::string &maps_ns);

 private:
  int do_compile(std::unique_ptr<llvm::Module> *mod, TableStorage &ts,
                 bool in_memory, const std::vector<const char *> &flags_cstr_in,
                 const std::vector<const char *> &flags_cstr_rem,
                 const std::string &main_path,
                 const std::unique_ptr<llvm::MemoryBuffer> &main_buf,
                 const std::string &id, FuncSource &func_src,
                 std::string &mod_src, bool use_internal_bpfh,
                 const std::string &maps_ns);

 private:
  std::map<std::string, std::unique_ptr<llvm::MemoryBuffer>> remapped_headers_;
  std::map<std::string, std::unique_ptr<llvm::MemoryBuffer>> remapped_footers_;
  llvm::LLVMContext *ctx_;
  unsigned flags_;
};

}  // namespace ebpf
