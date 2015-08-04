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
#include <algorithm>
#include <fcntl.h>
#include <ftw.h>
#include <map>
#include <stdio.h>
#include <string>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <vector>
#include <linux/bpf.h>

#include <llvm/ADT/STLExtras.h>
#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/ExecutionEngine/SectionMemoryManager.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/IR/IRPrintingPasses.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/FormattedStream.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>

#include "exception.h"
#include "frontends/b/loader.h"
#include "frontends/clang/loader.h"
#include "frontends/clang/b_frontend_action.h"
#include "bpf_module.h"
#include "kbuild_helper.h"
#include "libbpf.h"

namespace ebpf {

using std::get;
using std::make_tuple;
using std::map;
using std::move;
using std::string;
using std::tuple;
using std::unique_ptr;
using std::vector;
using namespace llvm;

const string BPFModule::FN_PREFIX = BPF_FN_PREFIX;

// Snooping class to remember the sections as the JIT creates them
class MyMemoryManager : public SectionMemoryManager {
 public:

  explicit MyMemoryManager(map<string, tuple<uint8_t *, uintptr_t>> *sections)
      : sections_(sections) {
  }

  virtual ~MyMemoryManager() {}
  uint8_t *allocateCodeSection(uintptr_t Size, unsigned Alignment,
                               unsigned SectionID,
                               StringRef SectionName) override {
    uint8_t *Addr = SectionMemoryManager::allocateCodeSection(Size, Alignment, SectionID, SectionName);
    //printf("allocateCodeSection: %s Addr %p Size %ld Alignment %d SectionID %d\n",
    //       SectionName.str().c_str(), (void *)Addr, Size, Alignment, SectionID);
    (*sections_)[SectionName.str()] = make_tuple(Addr, Size);
    return Addr;
  }
  uint8_t *allocateDataSection(uintptr_t Size, unsigned Alignment,
                               unsigned SectionID, StringRef SectionName,
                               bool isReadOnly) override {
    uint8_t *Addr = SectionMemoryManager::allocateDataSection(Size, Alignment, SectionID, SectionName, isReadOnly);
    //printf("allocateDataSection: %s Addr %p Size %ld Alignment %d SectionID %d RO %d\n",
    //       SectionName.str().c_str(), (void *)Addr, Size, Alignment, SectionID, isReadOnly);
    (*sections_)[SectionName.str()] = make_tuple(Addr, Size);
    return Addr;
  }
  map<string, tuple<uint8_t *, uintptr_t>> *sections_;
};

BPFModule::BPFModule(unsigned flags)
    : flags_(flags), ctx_(new LLVMContext) {
  LLVMInitializeBPFTarget();
  LLVMInitializeBPFTargetMC();
  LLVMInitializeBPFTargetInfo();
  LLVMInitializeBPFAsmPrinter();
  LLVMLinkInMCJIT(); /* call empty function to force linking of MCJIT */
}

BPFModule::~BPFModule() {
  engine_.reset();
  ctx_.reset();
}

// load an entire c file as a module
int BPFModule::load_cfile(const string &file, bool in_memory) {
  clang_loader_ = make_unique<ClangLoader>(&*ctx_);
  unique_ptr<Module> mod;
  if (clang_loader_->parse(&mod, &tables_, file, in_memory))
    return -1;
  mod_ = &*mod;

  mod_->setDataLayout("e-m:e-p:64:64-i64:64-n32:64-S128");
  mod_->setTargetTriple("bpf-pc-linux");

  for (auto fn = mod_->getFunctionList().begin(); fn != mod_->getFunctionList().end(); ++fn)
    fn->addFnAttr(Attribute::AlwaysInline);

  string err;
  engine_ = unique_ptr<ExecutionEngine>(EngineBuilder(move(mod))
      .setErrorStr(&err)
      .setMCJITMemoryManager(make_unique<MyMemoryManager>(&sections_))
      .setMArch("bpf")
      .create());
  if (!engine_) {
    fprintf(stderr, "Could not create ExecutionEngine: %s\n", err.c_str());
    return -1;
  }

  return 0;
}

// NOTE: this is a duplicate of the above, but planning to deprecate if we
// settle on clang as the frontend

// Load in a pre-built list of functions into the initial Module object, then
// build an ExecutionEngine.
int BPFModule::load_includes(const string &tmpfile) {
  clang_loader_ = make_unique<ClangLoader>(&*ctx_);
  unique_ptr<Module> mod;
  if (clang_loader_->parse(&mod, &tables_, tmpfile, false))
    return -1;
  mod_ = &*mod;

  mod_->setDataLayout("e-m:e-p:64:64-i64:64-n32:64-S128");
  mod_->setTargetTriple("bpf-pc-linux");

  for (auto fn = mod_->getFunctionList().begin(); fn != mod_->getFunctionList().end(); ++fn)
    fn->addFnAttr(Attribute::AlwaysInline);

  string err;
  engine_ = unique_ptr<ExecutionEngine>(EngineBuilder(move(mod))
      .setErrorStr(&err)
      .setMCJITMemoryManager(make_unique<MyMemoryManager>(&sections_))
      .setMArch("bpf")
      .create());
  if (!engine_) {
    fprintf(stderr, "Could not create ExecutionEngine: %s\n", err.c_str());
    return -1;
  }

  return 0;
}

void BPFModule::dump_ir() {
  legacy::PassManager PM;
  PM.add(createPrintModulePass(outs()));
  PM.run(*mod_);
}

int BPFModule::finalize() {
  if (verifyModule(*mod_, &errs())) {
    if (flags_ & 1)
      dump_ir();
    return -1;
  }

  legacy::PassManager PM;
  PassManagerBuilder PMB;
  PMB.OptLevel = 3;
  PM.add(createFunctionInliningPass());
  PM.add(createAlwaysInlinerPass());
  PMB.populateModulePassManager(PM);
  if (flags_ & 1)
    PM.add(createPrintModulePass(outs()));
  PM.run(*mod_);

  engine_->finalizeObject();

  // give functions an id
  for (auto section : sections_)
    if (!strncmp(FN_PREFIX.c_str(), section.first.c_str(), FN_PREFIX.size()))
      function_names_.push_back(section.first);

  for (auto table : *tables_)
    table_names_.push_back(table.first);

  return 0;
}

size_t BPFModule::num_functions() const {
  return function_names_.size();
}

const char * BPFModule::function_name(size_t id) const {
  if (id >= function_names_.size())
    return nullptr;
  return function_names_[id].c_str() + FN_PREFIX.size();
}

uint8_t * BPFModule::function_start(size_t id) const {
  if (id >= function_names_.size())
    return nullptr;
  auto section = sections_.find(function_names_[id]);
  if (section == sections_.end())
    return nullptr;
  return get<0>(section->second);
}

uint8_t * BPFModule::function_start(const string &name) const {
  auto section = sections_.find(FN_PREFIX + name);
  if (section == sections_.end())
    return nullptr;

  return get<0>(section->second);
}

size_t BPFModule::function_size(size_t id) const {
  if (id >= function_names_.size())
    return 0;
  auto section = sections_.find(function_names_[id]);
  if (section == sections_.end())
    return 0;
  return get<1>(section->second);
}

size_t BPFModule::function_size(const string &name) const {
  auto section = sections_.find(FN_PREFIX + name);
  if (section == sections_.end())
    return 0;

  return get<1>(section->second);
}

char * BPFModule::license() const {
  auto section = sections_.find("license");
  if (section == sections_.end())
    return nullptr;

  return (char *)get<0>(section->second);
}

unsigned BPFModule::kern_version() const {
  auto section = sections_.find("version");
  if (section == sections_.end())
    return 0;

  return *(unsigned *)get<0>(section->second);
}

size_t BPFModule::num_tables() const {
  return table_names_.size();
}

int BPFModule::table_fd(const string &name) const {
  int fd = b_loader_ ? b_loader_->get_table_fd(name) : -1;
  if (fd >= 0) return fd;
  auto table_it = tables_->find(name);
  if (table_it == tables_->end()) return -1;
  return table_it->second.fd;
}

int BPFModule::table_fd(size_t id) const {
  if (id >= table_names_.size()) return -1;
  return table_fd(table_names_[id]);
}

const char * BPFModule::table_name(size_t id) const {
  if (id >= table_names_.size()) return nullptr;
  return table_names_[id].c_str();
}

const char * BPFModule::table_key_desc(size_t id) const {
  if (id >= table_names_.size()) return nullptr;
  return table_key_desc(table_names_[id]);
}

const char * BPFModule::table_key_desc(const string &name) const {
  if (b_loader_) return nullptr;
  auto table_it = tables_->find(name);
  if (table_it == tables_->end()) return nullptr;
  return table_it->second.key_desc.c_str();
}

const char * BPFModule::table_leaf_desc(size_t id) const {
  if (id >= table_names_.size()) return nullptr;
  return table_leaf_desc(table_names_[id]);
}

const char * BPFModule::table_leaf_desc(const string &name) const {
  if (b_loader_) return nullptr;
  auto table_it = tables_->find(name);
  if (table_it == tables_->end()) return nullptr;
  return table_it->second.leaf_desc.c_str();
}

// load a B file, which comes in two parts
int BPFModule::load_b(const string &filename, const string &proto_filename) {
  if (!sections_.empty()) {
    fprintf(stderr, "Program already initialized\n");
    return -1;
  }
  if (filename.empty() || proto_filename.empty()) {
    fprintf(stderr, "Invalid filenames\n");
    return -1;
  }

  // Helpers are inlined in the following file (C). Load the definitions and
  // pass the partially compiled module to the B frontend to continue with.
  if (int rc = load_includes(BCC_INSTALL_PREFIX "/share/bcc/include/bcc/helpers.h"))
    return rc;

  b_loader_.reset(new BLoader);
  if (int rc = b_loader_->parse(mod_, filename, proto_filename))
    return rc;
  if (int rc = finalize())
    return rc;
  return 0;
}

// load a C file
int BPFModule::load_c(const string &filename) {
  if (!sections_.empty()) {
    fprintf(stderr, "Program already initialized\n");
    return -1;
  }
  if (filename.empty()) {
    fprintf(stderr, "Invalid filename\n");
    return -1;
  }
  if (int rc = load_cfile(filename, false))
    return rc;
  if (int rc = finalize())
    return rc;
  return 0;
}

// load a C text string
int BPFModule::load_string(const string &text) {
  if (!sections_.empty()) {
    fprintf(stderr, "Program already initialized\n");
    return -1;
  }
  if (int rc = load_cfile(text, true))
    return rc;

  if (int rc = finalize())
    return rc;
  return 0;
}

} // namespace ebpf
