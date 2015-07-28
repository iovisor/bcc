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

#include <clang/Basic/FileManager.h>
#include <clang/Basic/TargetInfo.h>
#include <clang/CodeGen/BackendUtil.h>
#include <clang/CodeGen/CodeGenAction.h>
#include <clang/Driver/Compilation.h>
#include <clang/Driver/Driver.h>
#include <clang/Driver/Job.h>
#include <clang/Driver/Tool.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/CompilerInvocation.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Frontend/FrontendDiagnostic.h>
#include <clang/Frontend/TextDiagnosticPrinter.h>
#include <clang/FrontendTool/Utils.h>

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
#include "parser.h"
#include "type_check.h"
#include "codegen_llvm.h"
#include "b_frontend_action.h"
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

int BPFModule::load_file_module(unique_ptr<llvm::Module> *mod, const string &file, bool in_memory) {
  using namespace clang;

  struct utsname un;
  uname(&un);
  char kdir[256];
  snprintf(kdir, sizeof(kdir), "%s/%s/build", KERNEL_MODULES_DIR, un.release);

  // clang needs to run inside the kernel dir
  DirStack dstack(kdir);
  if (!dstack.ok())
    return -1;

  string abs_file;
  if (in_memory) {
    abs_file = "<bcc-memory-buffer>";
  } else {
    if (file.substr(0, 1) == "/")
      abs_file = file;
    else
      abs_file = string(dstack.cwd()) + "/" + file;
  }

  vector<const char *> flags_cstr({"-O0", "-emit-llvm", "-I", dstack.cwd(),
                                   "-Wno-deprecated-declarations",
                                   "-x", "c", "-c", abs_file.c_str()});

  KBuildHelper kbuild_helper;
  vector<string> kflags;
  if (kbuild_helper.get_flags(un.release, &kflags))
    return -1;
  kflags.push_back("-include");
  kflags.push_back(BCC_INSTALL_PREFIX "/share/bcc/include/bcc/helpers.h");
  kflags.push_back("-I");
  kflags.push_back(BCC_INSTALL_PREFIX "/share/bcc/include");
  for (auto it = kflags.begin(); it != kflags.end(); ++it)
    flags_cstr.push_back(it->c_str());

  // set up the error reporting class
  IntrusiveRefCntPtr<DiagnosticOptions> diag_opts(new DiagnosticOptions());
  auto diag_client = new TextDiagnosticPrinter(llvm::errs(), &*diag_opts);

  IntrusiveRefCntPtr<DiagnosticIDs> DiagID(new DiagnosticIDs());
  DiagnosticsEngine diags(DiagID, &*diag_opts, diag_client);

  // set up the command line argument wrapper
  driver::Driver drv("", "x86_64-unknown-linux-gnu", diags);
  drv.setTitle("bcc-clang-driver");
  drv.setCheckInputsExist(false);

  unique_ptr<driver::Compilation> compilation(drv.BuildCompilation(flags_cstr));
  if (!compilation)
    return -1;

  // expect exactly 1 job, otherwise error
  const driver::JobList &jobs = compilation->getJobs();
  if (jobs.size() != 1 || !isa<driver::Command>(*jobs.begin())) {
    SmallString<256> msg;
    llvm::raw_svector_ostream os(msg);
    jobs.Print(os, "; ", true);
    diags.Report(diag::err_fe_expected_compiler_job) << os.str();
    return -1;
  }

  const driver::Command &cmd = cast<driver::Command>(*jobs.begin());
  if (llvm::StringRef(cmd.getCreator().getName()) != "clang") {
    diags.Report(diag::err_fe_expected_clang_command);
    return -1;
  }

  // Initialize a compiler invocation object from the clang (-cc1) arguments.
  const driver::ArgStringList &ccargs = cmd.getArguments();

  // first pass
  auto invocation1 = make_unique<CompilerInvocation>();
  if (!CompilerInvocation::CreateFromArgs(*invocation1, const_cast<const char **>(ccargs.data()),
                                          const_cast<const char **>(ccargs.data()) + ccargs.size(), diags))
    return -1;

  if (in_memory) {
    invocation1->getPreprocessorOpts().addRemappedFile("<bcc-memory-buffer>",
                                                       llvm::MemoryBuffer::getMemBuffer(file).release());
    invocation1->getFrontendOpts().Inputs.clear();
    invocation1->getFrontendOpts().Inputs.push_back(FrontendInputFile("<bcc-memory-buffer>", IK_C));
  }

  CompilerInstance compiler1;
  compiler1.setInvocation(invocation1.release());
  compiler1.createDiagnostics();

  // capture the rewritten c file
  string out_str;
  llvm::raw_string_ostream os(out_str);
  BFrontendAction bact(os);
  if (!compiler1.ExecuteAction(bact))
    return -1;
  // this contains the open FDs
  tables_ = bact.take_tables();

  // second pass, clear input and take rewrite buffer
  auto invocation2 = make_unique<CompilerInvocation>();
  if (!CompilerInvocation::CreateFromArgs(*invocation2, const_cast<const char **>(ccargs.data()),
                                          const_cast<const char **>(ccargs.data()) + ccargs.size(), diags))
    return -1;
  CompilerInstance compiler2;
  invocation2->getPreprocessorOpts().addRemappedFile("<bcc-memory-buffer>",
                                                     llvm::MemoryBuffer::getMemBuffer(out_str).release());
  invocation2->getFrontendOpts().Inputs.clear();
  invocation2->getFrontendOpts().Inputs.push_back(FrontendInputFile("<bcc-memory-buffer>", IK_C));
  // suppress warnings in the 2nd pass, but bail out on errors (our fault)
  invocation2->getDiagnosticOpts().IgnoreWarnings = true;
  compiler2.setInvocation(invocation2.release());
  compiler2.createDiagnostics();

  EmitLLVMOnlyAction ir_act(&*ctx_);
  if (!compiler2.ExecuteAction(ir_act))
    return -1;
  *mod = ir_act.takeModule();

  return 0;
}

// load an entire c file as a module
int BPFModule::load_cfile(const string &file, bool in_memory) {
  unique_ptr<Module> mod;
  if (load_file_module(&mod, file, in_memory))
    return -1;
  mod_ = &*mod;

  mod_->setDataLayout("e-m:e-i64:64-f80:128-n8:16:32:64-S128");
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
  unique_ptr<Module> mod;
  if (load_file_module(&mod, tmpfile, false))
    return -1;
  mod_ = &*mod;

  mod_->setDataLayout("e-m:e-i64:64-f80:128-n8:16:32:64-S128");
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

int BPFModule::parse() {
  int rc;

  proto_parser_ = make_unique<ebpf::cc::Parser>(proto_filename_);
  rc = proto_parser_->parse();
  if (rc) {
    fprintf(stderr, "In file: %s\n", filename_.c_str());
    return rc;
  }

  parser_ = make_unique<ebpf::cc::Parser>(filename_);
  rc = parser_->parse();
  if (rc) {
    fprintf(stderr, "In file: %s\n", filename_.c_str());
    return rc;
  }

  //ebpf::cc::Printer printer(stderr);
  //printer.visit(parser_->root_node_);

  ebpf::cc::TypeCheck type_check(parser_->scopes_.get(), proto_parser_->scopes_.get(), parser_->pragmas_);
  auto ret = type_check.visit(parser_->root_node_);
  if (get<0>(ret) != 0 || get<1>(ret).size()) {
    fprintf(stderr, "Type error @line=%d: %s\n", get<0>(ret), get<1>(ret).c_str());
    return -1;
  }

  if (load_includes(BCC_INSTALL_PREFIX "/share/bcc/include/bcc/helpers.h") < 0)
    return -1;

  codegen_ = ebpf::make_unique<ebpf::cc::CodegenLLVM>(mod_, parser_->scopes_.get(), proto_parser_->scopes_.get());
  ret = codegen_->visit(parser_->root_node_);
  if (get<0>(ret) != 0 || get<1>(ret).size()) {
    fprintf(stderr, "Codegen error @line=%d: %s\n", get<0>(ret), get<1>(ret).c_str());
    return get<0>(ret);
  }

  return 0;
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
  int fd = codegen_ ? codegen_->get_table_fd(name) : -1;
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
  if (codegen_) return nullptr;
  auto table_it = tables_->find(name);
  if (table_it == tables_->end()) return nullptr;
  return table_it->second.key_desc.c_str();
}

const char * BPFModule::table_leaf_desc(size_t id) const {
  if (id >= table_names_.size()) return nullptr;
  return table_leaf_desc(table_names_[id]);
}

const char * BPFModule::table_leaf_desc(const string &name) const {
  if (codegen_) return nullptr;
  auto table_it = tables_->find(name);
  if (table_it == tables_->end()) return nullptr;
  return table_it->second.leaf_desc.c_str();
}

int BPFModule::load(const string &filename, const string &proto_filename) {
  if (!sections_.empty()) {
    fprintf(stderr, "Program already initialized\n");
    return -1;
  }
  filename_ = filename;
  proto_filename_ = proto_filename;
  if (proto_filename_.empty()) {
    // direct load of .b file
    if (int rc = load_cfile(filename_, false))
      return rc;
  } else {
    // old lex .b file
    if (int rc = parse())
      return rc;
  }
  if (int rc = finalize())
    return rc;
  return 0;
}

int BPFModule::load_string(const string &text) {
  if (!sections_.empty()) {
    fprintf(stderr, "Program already initialized\n");
    return -1;
  }
  filename_ = "<memory>";
  if (int rc = load_cfile(text, true))
    return rc;

  if (int rc = finalize())
    return rc;
  return 0;
}

} // namespace ebpf
