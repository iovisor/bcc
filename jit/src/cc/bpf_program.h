/*
 * ====================================================================
 * Copyright (c) 2015, PLUMgrid, http://plumgrid.com
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

#include <stdint.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace llvm {
class ExecutionEngine;
class Module;
}

namespace ebpf {

namespace cc {
class CodegenLLVM;
class Parser;
}

class BPFProgram {
 private:
  int init_engine();
  int parse();
  int finalize();
  void dump_ir();
  std::string load_helper() const;
 public:
  BPFProgram(unsigned flags);
  ~BPFProgram();
  int load(const std::string &filename, const std::string &proto_filename);
  uint8_t * start(const std::string &name) const;
  size_t size(const std::string &name) const;
  int table_fd(const std::string &name) const;
  char * license() const;
 private:
  unsigned flags_;  // 0x1 for printing
  std::string filename_;
  std::string proto_filename_;
  std::unique_ptr<llvm::ExecutionEngine> engine_;
  llvm::Module *mod_;
  std::unique_ptr<ebpf::cc::Parser> parser_;
  std::unique_ptr<ebpf::cc::Parser> proto_parser_;
  std::unique_ptr<ebpf::cc::CodegenLLVM> codegen_;
  std::map<std::string, std::tuple<uint8_t *, uintptr_t>> sections_;
};

}  // namespace ebpf
