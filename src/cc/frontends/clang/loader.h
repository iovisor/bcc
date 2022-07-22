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

#include <clang/Frontend/CompilerInvocation.h>

#include <functional>
#include <map>
#include <memory>
#include <string>

#include "table_storage.h"
#include "vendor/optional.hpp"

using std::experimental::nullopt;
using std::experimental::optional;

namespace llvm {
class Module;
class LLVMContext;
class MemoryBuffer;
}

namespace ebpf {

struct FuncInfo {
  uint8_t *start_ = nullptr;
  size_t size_ = 0;
  std::string section_;
  std::string src_;
  std::string src_rewritten_;
  // dummy constructor so emplace() works
  FuncInfo(int i) {}
};

class ProgFuncInfo {
 public:
  ProgFuncInfo() {}
  void clear() {
    funcs_.clear();
    func_idx_.clear();
  }
  optional<FuncInfo &> get_func(std::string name);
  optional<FuncInfo &> get_func(size_t id);
  optional<std::string &> func_name(size_t id);
  optional<FuncInfo &> add_func(std::string name);
  size_t num_funcs() { return funcs_.size(); }
  void for_each_func(std::function<void(std::string, FuncInfo &)> cb);

 private:
  std::map<std::string, FuncInfo> funcs_;
  std::map<uint32_t, std::string> func_idx_;
};

class ClangLoader {
 public:
  explicit ClangLoader(llvm::LLVMContext *ctx, unsigned flags);
  ~ClangLoader();
  int parse(std::unique_ptr<llvm::Module> *mod, TableStorage &ts,
            const std::string &file, bool in_memory, const char *cflags[],
            int ncflags, const std::string &id, ProgFuncInfo &prog_func_info,
            std::string &mod_src, const std::string &maps_ns,
            fake_fd_map_def &fake_fd_map,
            std::map<std::string, std::vector<std::string>> &perf_events);

 private:
  int do_compile(std::unique_ptr<llvm::Module> *mod, TableStorage &ts,
                 bool in_memory, const std::vector<const char *> &flags_cstr_in,
                 const std::vector<const char *> &flags_cstr_rem,
                 const std::string &main_path,
                 const std::unique_ptr<llvm::MemoryBuffer> &main_buf,
                 const std::string &id, ProgFuncInfo &prog_func_info,
                 std::string &mod_src, bool use_internal_bpfh,
                 const std::string &maps_ns, fake_fd_map_def &fake_fd_map,
                 std::map<std::string, std::vector<std::string>> &perf_events);
  void add_remapped_includes(clang::CompilerInvocation& invocation);
  void add_main_input(clang::CompilerInvocation& invocation,
                      const std::string& main_path,
                      llvm::MemoryBuffer *main_buf);

 private:
  std::map<std::string, std::unique_ptr<llvm::MemoryBuffer>> remapped_headers_;
  std::map<std::string, std::unique_ptr<llvm::MemoryBuffer>> remapped_footers_;
  llvm::LLVMContext *ctx_;
  unsigned flags_;
};

}  // namespace ebpf
