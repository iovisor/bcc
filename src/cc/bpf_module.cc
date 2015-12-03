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
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/IRPrintingPasses.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/FormattedStream.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/TargetSelect.h>
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

typedef int (* sscanf_fn) (const char *, void *);
typedef int (* snprintf_fn) (char *, size_t, const void *);

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
  InitializeNativeTarget();
  InitializeNativeTargetAsmPrinter();
  LLVMInitializeBPFTarget();
  LLVMInitializeBPFTargetMC();
  LLVMInitializeBPFTargetInfo();
  LLVMInitializeBPFAsmPrinter();
  LLVMLinkInMCJIT(); /* call empty function to force linking of MCJIT */
}

BPFModule::~BPFModule() {
  engine_.reset();
  rw_engine_.reset();
  ctx_.reset();
}

static void debug_printf(Module *mod, IRBuilder<> &B, const string &fmt, vector<Value *> args) {
  GlobalVariable *fmt_gvar = B.CreateGlobalString(fmt, "fmt");
  args.insert(args.begin(), B.CreateInBoundsGEP(fmt_gvar, vector<Value *>({B.getInt64(0), B.getInt64(0)})));
  args.insert(args.begin(), B.getInt64((uintptr_t)stderr));
  Function *fprintf_fn = mod->getFunction("fprintf");
  if (!fprintf_fn) {
    vector<Type *> fprintf_fn_args({B.getInt64Ty(), B.getInt8PtrTy()});
    FunctionType *fprintf_fn_type = FunctionType::get(B.getInt32Ty(), fprintf_fn_args, /*isvarArg=*/true);
    fprintf_fn = Function::Create(fprintf_fn_type, GlobalValue::ExternalLinkage, "fprintf", mod);
    fprintf_fn->setCallingConv(CallingConv::C);
    fprintf_fn->addFnAttr(Attribute::NoUnwind);
  }
  B.CreateCall(fprintf_fn, args);
}

// recursive helper to capture the arguments
static void parse_type(IRBuilder<> &B, vector<Value *> *args, string *fmt,
                       Type *type, Value *out, bool is_writer) {
  if (StructType *st = dyn_cast<StructType>(type)) {
    *fmt += "{ ";
    unsigned idx = 0;
    for (auto field : st->elements()) {
      parse_type(B, args, fmt, field, B.CreateStructGEP(type, out, idx++), is_writer);
      *fmt += " ";
    }
    *fmt += "}";
  } else if (IntegerType *it = dyn_cast<IntegerType>(type)) {
    if (is_writer)
      *fmt += "0x";
    if (it->getBitWidth() <= 8)
      *fmt += "%hh";
    else if (it->getBitWidth() <= 16)
      *fmt += "%h";
    else if (it->getBitWidth() <= 32)
      *fmt += "%";
    else
      *fmt += "%l";
    if (is_writer)
      *fmt += "x";
    else
      *fmt += "i";
    args->push_back(is_writer ? B.CreateLoad(out) : out);
  }
}

Function * BPFModule::make_reader(Module *mod, Type *type) {
  auto fn_it = readers_.find(type);
  if (fn_it != readers_.end())
    return fn_it->second;

  // int read(const char *in, Type *out) {
  //   int n = sscanf(in, "{ %i ... }", &out->field1, ...);
  //   if (n != num_fields) return -1;
  //   return 0;
  // }

  IRBuilder<> B(*ctx_);

  vector<Type *> fn_args({B.getInt8PtrTy(), PointerType::getUnqual(type)});
  FunctionType *fn_type = FunctionType::get(B.getInt32Ty(), fn_args, /*isVarArg=*/false);
  Function *fn = Function::Create(fn_type, GlobalValue::ExternalLinkage,
                                  "reader" + std::to_string(readers_.size()), mod);
  auto arg_it = fn->arg_begin();
  Argument *arg_in = &*arg_it;
  ++arg_it;
  arg_in->setName("in");
  Argument *arg_out = &*arg_it;
  ++arg_it;
  arg_out->setName("out");

  BasicBlock *label_entry = BasicBlock::Create(*ctx_, "entry", fn);
  BasicBlock *label_exit = BasicBlock::Create(*ctx_, "exit", fn);
  B.SetInsertPoint(label_entry);

  vector<Value *> args({arg_in, nullptr});
  string fmt;
  parse_type(B, &args, &fmt, type, arg_out, false);

  GlobalVariable *fmt_gvar = B.CreateGlobalString(fmt, "fmt");

  args[1] = B.CreateInBoundsGEP(fmt_gvar, vector<Value *>({B.getInt64(0), B.getInt64(0)}));

  if (0)
    debug_printf(mod, B, "%p %p\n", vector<Value *>({arg_in, arg_out}));

  vector<Type *> sscanf_fn_args({B.getInt8PtrTy(), B.getInt8PtrTy()});
  FunctionType *sscanf_fn_type = FunctionType::get(B.getInt32Ty(), sscanf_fn_args, /*isVarArg=*/true);
  Function *sscanf_fn = mod->getFunction("sscanf");
  if (!sscanf_fn)
    sscanf_fn = Function::Create(sscanf_fn_type, GlobalValue::ExternalLinkage, "sscanf", mod);
  sscanf_fn->setCallingConv(CallingConv::C);
  sscanf_fn->addFnAttr(Attribute::NoUnwind);

  CallInst *call = B.CreateCall(sscanf_fn, args);
  call->setTailCall(true);

  BasicBlock *label_then = BasicBlock::Create(*ctx_, "then", fn);

  Value *is_neq = B.CreateICmpNE(call, B.getInt32(args.size() - 2));
  B.CreateCondBr(is_neq, label_then, label_exit);

  B.SetInsertPoint(label_then);
  B.CreateRet(B.getInt32(-1));

  B.SetInsertPoint(label_exit);
  B.CreateRet(B.getInt32(0));

  readers_[type] = fn;
  return fn;
}

Function * BPFModule::make_writer(Module *mod, Type *type) {
  auto fn_it = writers_.find(type);
  if (fn_it != writers_.end())
    return fn_it->second;

  // int write(int len, char *out, Type *in) {
  //   return snprintf(out, len, "{ %i ... }", out->field1, ...);
  // }

  IRBuilder<> B(*ctx_);

  vector<Type *> fn_args({B.getInt8PtrTy(), B.getInt64Ty(), PointerType::getUnqual(type)});
  FunctionType *fn_type = FunctionType::get(B.getInt32Ty(), fn_args, /*isVarArg=*/false);
  Function *fn = Function::Create(fn_type, GlobalValue::ExternalLinkage,
                                  "writer" + std::to_string(writers_.size()), mod);
  auto arg_it = fn->arg_begin();
  Argument *arg_out = &*arg_it;
  ++arg_it;
  arg_out->setName("out");
  Argument *arg_len = &*arg_it;
  ++arg_it;
  arg_len->setName("len");
  Argument *arg_in = &*arg_it;
  ++arg_it;
  arg_in->setName("in");

  BasicBlock *label_entry = BasicBlock::Create(*ctx_, "entry", fn);
  B.SetInsertPoint(label_entry);

  vector<Value *> args({arg_out, B.CreateZExt(arg_len, B.getInt64Ty()), nullptr});
  string fmt;
  parse_type(B, &args, &fmt, type, arg_in, true);

  GlobalVariable *fmt_gvar = B.CreateGlobalString(fmt, "fmt");

  args[2] = B.CreateInBoundsGEP(fmt_gvar, vector<Value *>({B.getInt64(0), B.getInt64(0)}));

  if (0)
    debug_printf(mod, B, "%d %p %p\n", vector<Value *>({arg_len, arg_out, arg_in}));

  vector<Type *> snprintf_fn_args({B.getInt8PtrTy(), B.getInt64Ty(), B.getInt8PtrTy()});
  FunctionType *snprintf_fn_type = FunctionType::get(B.getInt32Ty(), snprintf_fn_args, /*isVarArg=*/true);
  Function *snprintf_fn = mod->getFunction("snprintf");
  if (!snprintf_fn)
    snprintf_fn = Function::Create(snprintf_fn_type, GlobalValue::ExternalLinkage, "snprintf", mod);
  snprintf_fn->setCallingConv(CallingConv::C);
  snprintf_fn->addFnAttr(Attribute::NoUnwind);

  CallInst *call = B.CreateCall(snprintf_fn, args);
  call->setTailCall(true);

  B.CreateRet(call);

  writers_[type] = fn;
  return fn;
}

unique_ptr<ExecutionEngine> BPFModule::finalize_rw(unique_ptr<Module> m) {
  Module *mod = &*m;

  run_pass_manager(*mod);

  string err;
  EngineBuilder builder(move(m));
  builder.setErrorStr(&err);
  builder.setUseOrcMCJITReplacement(true);
  auto engine = unique_ptr<ExecutionEngine>(builder.create());
  if (!engine)
    fprintf(stderr, "Could not create ExecutionEngine: %s\n", err.c_str());
  return engine;
}

// load an entire c file as a module
int BPFModule::load_cfile(const string &file, bool in_memory) {
  clang_loader_ = make_unique<ClangLoader>(&*ctx_, flags_);
  if (clang_loader_->parse(&mod_, &tables_, file, in_memory))
    return -1;
  return 0;
}

// NOTE: this is a duplicate of the above, but planning to deprecate if we
// settle on clang as the frontend

// Load in a pre-built list of functions into the initial Module object, then
// build an ExecutionEngine.
int BPFModule::load_includes(const string &tmpfile) {
  clang_loader_ = make_unique<ClangLoader>(&*ctx_, flags_);
  if (clang_loader_->parse(&mod_, &tables_, tmpfile, false))
    return -1;
  return 0;
}

int BPFModule::annotate() {
  for (auto fn = mod_->getFunctionList().begin(); fn != mod_->getFunctionList().end(); ++fn)
    fn->addFnAttr(Attribute::AlwaysInline);

  // separate module to hold the reader functions
  auto m = make_unique<Module>("sscanf", *ctx_);

  size_t id = 0;
  for (auto &table : *tables_) {
    table_names_[table.name] = id++;
    GlobalValue *gvar = mod_->getNamedValue(table.name);
    if (!gvar) continue;
    if (PointerType *pt = dyn_cast<PointerType>(gvar->getType())) {
      if (StructType *st = dyn_cast<StructType>(pt->getElementType())) {
        if (st->getNumElements() < 2) continue;
        Type *key_type = st->elements()[0];
        Type *leaf_type = st->elements()[1];
        table.key_sscanf = make_reader(&*m, key_type);
        if (!table.key_sscanf)
          errs() << "Failed to compile sscanf for " << *key_type << "\n";
        table.leaf_sscanf = make_reader(&*m, leaf_type);
        if (!table.leaf_sscanf)
          errs() << "Failed to compile sscanf for " << *leaf_type << "\n";
        table.key_snprintf = make_writer(&*m, key_type);
        if (!table.key_snprintf)
          errs() << "Failed to compile snprintf for " << *key_type << "\n";
        table.leaf_snprintf = make_writer(&*m, leaf_type);
        if (!table.leaf_snprintf)
          errs() << "Failed to compile snprintf for " << *leaf_type << "\n";
      }
    }
  }

  rw_engine_ = finalize_rw(move(m));
  if (rw_engine_)
    rw_engine_->finalizeObject();

  return 0;
}

void BPFModule::dump_ir(Module &mod) {
  legacy::PassManager PM;
  PM.add(createPrintModulePass(errs()));
  PM.run(mod);
}

int BPFModule::run_pass_manager(Module &mod) {
  if (verifyModule(mod, &errs())) {
    if (flags_ & 1)
      dump_ir(mod);
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
  PM.run(mod);
  return 0;
}

int BPFModule::finalize() {
  Module *mod = &*mod_;

  mod->setDataLayout("e-m:e-p:64:64-i64:64-n32:64-S128");
  mod->setTargetTriple("bpf-pc-linux");

  string err;
  EngineBuilder builder(move(mod_));
  builder.setErrorStr(&err);
  builder.setMCJITMemoryManager(make_unique<MyMemoryManager>(&sections_));
  builder.setMArch("bpf");
  builder.setUseOrcMCJITReplacement(true);
  engine_ = unique_ptr<ExecutionEngine>(builder.create());
  if (!engine_) {
    fprintf(stderr, "Could not create ExecutionEngine: %s\n", err.c_str());
    return -1;
  }

  if (int rc = run_pass_manager(*mod))
    return rc;

  engine_->finalizeObject();

  // give functions an id
  for (auto section : sections_)
    if (!strncmp(FN_PREFIX.c_str(), section.first.c_str(), FN_PREFIX.size()))
      function_names_.push_back(section.first);

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
  return tables_->size();
}

size_t BPFModule::table_id(const string &name) const {
  auto it = table_names_.find(name);
  if (it == table_names_.end()) return ~0ull;
  return it->second;
}

int BPFModule::table_fd(const string &name) const {
  return table_fd(table_id(name));
}

int BPFModule::table_fd(size_t id) const {
  if (id >= tables_->size()) return -1;
  return (*tables_)[id].fd;
}

int BPFModule::table_type(const string &name) const {
  return table_type(table_id(name));
}

int BPFModule::table_type(size_t id) const {
  if (id >= tables_->size()) return -1;
  return (*tables_)[id].type;
}

const char * BPFModule::table_name(size_t id) const {
  if (id >= tables_->size()) return nullptr;
  return (*tables_)[id].name.c_str();
}

const char * BPFModule::table_key_desc(size_t id) const {
  if (b_loader_) return nullptr;
  if (id >= tables_->size()) return nullptr;
  return (*tables_)[id].key_desc.c_str();
}

const char * BPFModule::table_key_desc(const string &name) const {
  return table_key_desc(table_id(name));
}

const char * BPFModule::table_leaf_desc(size_t id) const {
  if (b_loader_) return nullptr;
  if (id >= tables_->size()) return nullptr;
  return (*tables_)[id].leaf_desc.c_str();
}

const char * BPFModule::table_leaf_desc(const string &name) const {
  return table_leaf_desc(table_id(name));
}
size_t BPFModule::table_key_size(size_t id) const {
  if (id >= tables_->size()) return 0;
  return (*tables_)[id].key_size;
}
size_t BPFModule::table_key_size(const string &name) const {
  return table_key_size(table_id(name));
}

size_t BPFModule::table_leaf_size(size_t id) const {
  if (id >= tables_->size()) return 0;
  return (*tables_)[id].leaf_size;
}
size_t BPFModule::table_leaf_size(const string &name) const {
  return table_leaf_size(table_id(name));
}

struct TableIterator {
  TableIterator(size_t key_size, size_t leaf_size)
      : key(new uint8_t[key_size]), leaf(new uint8_t[leaf_size]) {
  }
  unique_ptr<uint8_t[]> key;
  unique_ptr<uint8_t[]> leaf;
  uint8_t keyb[512];
};

int BPFModule::table_key_printf(size_t id, char *buf, size_t buflen, const void *key) {
  if (id >= tables_->size()) return -1;
  const TableDesc &desc = (*tables_)[id];
  if (!desc.key_snprintf) {
    fprintf(stderr, "Key snprintf not available\n");
    return -1;
  }
  snprintf_fn fn = (snprintf_fn)rw_engine_->getPointerToFunction(desc.key_snprintf);
  if (!fn) {
    fprintf(stderr, "Key snprintf not available in JIT Engine\n");
    return -1;
  }
  int rc = (*fn)(buf, buflen, key);
  if (rc < 0) {
    perror("snprintf");
    return -1;
  }
  if ((size_t)rc >= buflen) {
    fprintf(stderr, "snprintf ran out of buffer space\n");
    return -1;
  }
  return 0;
}

int BPFModule::table_leaf_printf(size_t id, char *buf, size_t buflen, const void *leaf) {
  if (id >= tables_->size()) return -1;
  const TableDesc &desc = (*tables_)[id];
  if (!desc.leaf_snprintf) {
    fprintf(stderr, "Key snprintf not available\n");
    return -1;
  }
  snprintf_fn fn = (snprintf_fn)rw_engine_->getPointerToFunction(desc.leaf_snprintf);
  if (!fn) {
    fprintf(stderr, "Leaf snprintf not available in JIT Engine\n");
    return -1;
  }
  int rc = (*fn)(buf, buflen, leaf);
  if (rc < 0) {
    perror("snprintf");
    return -1;
  }
  if ((size_t)rc >= buflen) {
    fprintf(stderr, "snprintf ran out of buffer space\n");
    return -1;
  }
  return 0;
}

int BPFModule::table_key_scanf(size_t id, const char *key_str, void *key) {
  if (id >= tables_->size()) return -1;
  const TableDesc &desc = (*tables_)[id];
  if (!desc.key_sscanf) {
    fprintf(stderr, "Key sscanf not available\n");
    return -1;
  }

  sscanf_fn fn = (sscanf_fn)rw_engine_->getPointerToFunction(desc.key_sscanf);
  if (!fn) {
    fprintf(stderr, "Key sscanf not available in JIT Engine\n");
    return -1;
  }
  int rc = (*fn)(key_str, key);
  if (rc != 0) {
    perror("sscanf");
    return -1;
  }
  return 0;
}

int BPFModule::table_leaf_scanf(size_t id, const char *leaf_str, void *leaf) {
  if (id >= tables_->size()) return -1;
  const TableDesc &desc = (*tables_)[id];
  if (!desc.leaf_sscanf) {
    fprintf(stderr, "Key sscanf not available\n");
    return -1;
  }

  sscanf_fn fn = (sscanf_fn)rw_engine_->getPointerToFunction(desc.leaf_sscanf);
  if (!fn) {
    fprintf(stderr, "Leaf sscanf not available in JIT Engine\n");
    return -1;
  }
  int rc = (*fn)(leaf_str, leaf);
  if (rc != 0) {
    perror("sscanf");
    return -1;
  }
  return 0;
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

  b_loader_.reset(new BLoader(flags_));
  if (int rc = b_loader_->parse(&*mod_, filename, proto_filename, &tables_))
    return rc;
  if (int rc = annotate())
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
  if (int rc = annotate())
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
  if (int rc = annotate())
    return rc;

  if (int rc = finalize())
    return rc;
  return 0;
}

} // namespace ebpf
