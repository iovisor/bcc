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

#include <stdint.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "bcc_exception.h"

namespace llvm {
class ExecutionEngine;
class Function;
class LLVMContext;
class Module;
class Type;
}

namespace ebpf {

// Options to enable different debug logging.
enum {
  // Debug output compiled LLVM IR.
  DEBUG_LLVM_IR = 0x1,
  // Debug output loaded BPF bytecode and register state on branches.
  DEBUG_BPF = 0x2,
  // Debug output pre-processor result.
  DEBUG_PREPROCESSOR = 0x4,
  // Debug output ASM instructions embedded with source.
  DEBUG_SOURCE = 0x8,
  // Debug output register state on all instructions in addition to DEBUG_BPF.
  DEBUG_BPF_REGISTER_STATE = 0x10,
};

class TableDesc;
class TableStorage;
class BLoader;
class ClangLoader;
class FuncSource;

class BPFModule {
 private:
  static const std::string FN_PREFIX;
  int init_engine();
  int parse(llvm::Module *mod);
  int finalize();
  int annotate();
  void annotate_light();
  std::unique_ptr<llvm::ExecutionEngine> finalize_rw(std::unique_ptr<llvm::Module> mod);
  std::string make_reader(llvm::Module *mod, llvm::Type *type);
  std::string make_writer(llvm::Module *mod, llvm::Type *type);
  void dump_ir(llvm::Module &mod);
  int load_file_module(std::unique_ptr<llvm::Module> *mod, const std::string &file, bool in_memory);
  int load_includes(const std::string &text);
  int load_cfile(const std::string &file, bool in_memory, const char *cflags[], int ncflags);
  int kbuild_flags(const char *uname_release, std::vector<std::string> *cflags);
  int run_pass_manager(llvm::Module &mod);
  StatusTuple sscanf(std::string fn_name, const char *str, void *val);
  StatusTuple snprintf(std::string fn_name, char *str, size_t sz,
                       const void *val);

 public:
  BPFModule(unsigned flags, TableStorage *ts = nullptr, bool rw_engine_enabled = true,
            const std::string &maps_ns = "");
  ~BPFModule();
  int load_b(const std::string &filename, const std::string &proto_filename);
  int load_c(const std::string &filename, const char *cflags[], int ncflags);
  int load_string(const std::string &text, const char *cflags[], int ncflags);
  std::string id() const { return id_; }
  std::string maps_ns() const { return maps_ns_; }
  size_t num_functions() const;
  uint8_t * function_start(size_t id) const;
  uint8_t * function_start(const std::string &name) const;
  const char * function_source(const std::string &name) const;
  const char * function_source_rewritten(const std::string &name) const;
  int annotate_prog_tag(const std::string &name, int fd,
			struct bpf_insn *insn, int prog_len);
  const char * function_name(size_t id) const;
  size_t function_size(size_t id) const;
  size_t function_size(const std::string &name) const;
  size_t num_tables() const;
  size_t table_id(const std::string &name) const;
  int table_fd(size_t id) const;
  int table_fd(const std::string &name) const;
  const char * table_name(size_t id) const;
  int table_type(const std::string &name) const;
  int table_type(size_t id) const;
  size_t table_max_entries(const std::string &name) const;
  size_t table_max_entries(size_t id) const;
  int table_flags(const std::string &name) const;
  int table_flags(size_t id) const;
  const char * table_key_desc(size_t id) const;
  const char * table_key_desc(const std::string &name) const;
  size_t table_key_size(size_t id) const;
  size_t table_key_size(const std::string &name) const;
  int table_key_printf(size_t id, char *buf, size_t buflen, const void *key);
  int table_key_scanf(size_t id, const char *buf, void *key);
  const char * table_leaf_desc(size_t id) const;
  const char * table_leaf_desc(const std::string &name) const;
  size_t table_leaf_size(size_t id) const;
  size_t table_leaf_size(const std::string &name) const;
  int table_leaf_printf(size_t id, char *buf, size_t buflen, const void *leaf);
  int table_leaf_scanf(size_t id, const char *buf, void *leaf);
  char * license() const;
  unsigned kern_version() const;
  TableStorage &table_storage() { return *ts_; }

 private:
  unsigned flags_;  // 0x1 for printing
  bool rw_engine_enabled_;
  bool used_b_loader_;
  std::string filename_;
  std::string proto_filename_;
  std::unique_ptr<llvm::LLVMContext> ctx_;
  std::unique_ptr<llvm::ExecutionEngine> engine_;
  std::unique_ptr<llvm::ExecutionEngine> rw_engine_;
  std::unique_ptr<llvm::Module> mod_;
  std::unique_ptr<FuncSource> func_src_;
  std::map<std::string, std::tuple<uint8_t *, uintptr_t>> sections_;
  std::vector<TableDesc *> tables_;
  std::map<std::string, size_t> table_names_;
  std::vector<std::string> function_names_;
  std::map<llvm::Type *, std::string> readers_;
  std::map<llvm::Type *, std::string> writers_;
  std::string id_;
  std::string maps_ns_;
  std::string mod_src_;
  std::map<std::string, std::string> src_dbg_fmap_;
  TableStorage *ts_;
  std::unique_ptr<TableStorage> local_ts_;
};

}  // namespace ebpf
