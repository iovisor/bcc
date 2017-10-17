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
namespace ebpf {

class SourceDebugger {
 public:
  SourceDebugger(
      llvm::Module *mod,
      std::map<std::string, std::tuple<uint8_t *, uintptr_t>> &sections,
      const std::string &fn_prefix, const std::string &mod_src,
      std::map<std::string, std::string> &src_dbg_fmap)
      : mod_(mod),
        sections_(sections),
        fn_prefix_(fn_prefix),
        mod_src_(mod_src),
        src_dbg_fmap_(src_dbg_fmap) {}
// Only support dump for llvm 6.x and later.
//
// The llvm 5.x, but not earlier versions, also supports create
// a dwarf context for source debugging based
// on a set of in-memory sections with slightly different interfaces.
// FIXME: possibly to support 5.x
//
#if LLVM_MAJOR_VERSION >= 6
  void dump();

 private:
  void adjustInstSize(uint64_t &Size, uint8_t byte0, uint8_t byte1);
  std::vector<std::string> buildLineCache();
  void dumpSrcLine(const std::vector<std::string> &LineCache,
                   const std::string &FileName, uint32_t Line,
                   uint32_t &CurrentSrcLine, llvm::raw_ostream &os);
  void getDebugSections(
      llvm::StringMap<std::unique_ptr<llvm::MemoryBuffer>> &DebugSections);
#else
  void dump() {
  }
#endif

 private:
  llvm::Module *mod_;
  const std::map<std::string, std::tuple<uint8_t *, uintptr_t>> &sections_;
  const std::string &fn_prefix_;
  const std::string &mod_src_;
  std::map<std::string, std::string> &src_dbg_fmap_;
};

}  // namespace ebpf
