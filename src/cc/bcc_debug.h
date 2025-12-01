/*
 * Copyright (c) 2017 Facebook, Inc.
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
#include "frontends/clang/loader.h"

namespace ebpf {

class SourceDebugger {
 public:
  SourceDebugger(llvm::Module *mod, sec_map_def &sections,
                 ProgFuncInfo &prog_func_info, const std::string &mod_src,
                 std::map<std::string, std::string> &src_dbg_fmap)
      : mod_(mod),
        sections_(sections),
        prog_func_info_(prog_func_info),
        mod_src_(mod_src),
        src_dbg_fmap_(src_dbg_fmap) {}
  void dump();

 private:
  void adjustInstSize(uint64_t &Size, uint8_t byte0, uint8_t byte1);
  std::vector<std::string> buildLineCache();
  void dumpSrcLine(const std::vector<std::string> &LineCache,
                   const std::string &FileName, uint32_t Line,
                   uint32_t &CurrentSrcLine, llvm::raw_ostream &os);
  void getDebugSections(
      llvm::StringMap<std::unique_ptr<llvm::MemoryBuffer>> &DebugSections);

 private:
  llvm::Module *mod_;
  const sec_map_def &sections_;
  ProgFuncInfo &prog_func_info_;
  const std::string &mod_src_;
  std::map<std::string, std::string> &src_dbg_fmap_;
};

}  // namespace ebpf
