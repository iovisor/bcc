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
#include <llvm-c/Transforms/IPO.h>

#include "bcc_exception.h"
#include "frontends/b/loader.h"
#include "frontends/clang/loader.h"
#include "frontends/clang/b_frontend_action.h"
#include "bpf_module.h"
#include "exported_files.h"
#include "kbuild_helper.h"
#include "shared_table.h"
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

BPFModule::BPFModule(unsigned flags, TableStorage *ts, const std::string &maps_ns)
    : flags_(flags),
      ctx_(new LLVMContext),
      id_(std::to_string((uintptr_t)this)),
      maps_ns_(maps_ns),
      ts_(ts) {
  InitializeNativeTarget();
  InitializeNativeTargetAsmPrinter();
  LLVMInitializeBPFTarget();
  LLVMInitializeBPFTargetMC();
  LLVMInitializeBPFTargetInfo();
  LLVMInitializeBPFAsmPrinter();
  LLVMLinkInMCJIT(); /* call empty function to force linking of MCJIT */
  if (!ts_) {
    local_ts_ = createSharedTableStorage();
    ts_ = &*local_ts_;
  }
}

static StatusTuple unimplemented_sscanf(const char *, void *) {
  return StatusTuple(-1, "sscanf unimplemented");
}
static StatusTuple unimplemented_snprintf(char *, size_t, const void *) {
  return StatusTuple(-1, "snprintf unimplemented");
}

BPFModule::~BPFModule() {
  for (auto &v : tables_) {
    v->key_sscanf = unimplemented_sscanf;
    v->leaf_sscanf = unimplemented_sscanf;
    v->key_snprintf = unimplemented_snprintf;
    v->leaf_snprintf = unimplemented_snprintf;
  }

  engine_.reset();
  rw_engine_.reset();
  ctx_.reset();

  ts_->DeletePrefix(Path({id_}));
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
  } else if (ArrayType *at = dyn_cast<ArrayType>(type)) {
    *fmt += "[ ";
    for (size_t i = 0; i < at->getNumElements(); ++i) {
      parse_type(B, args, fmt, at->getElementType(), B.CreateStructGEP(type, out, i), is_writer);
      *fmt += " ";
    }
    *fmt += "]";
  } else if (isa<PointerType>(type)) {
    *fmt += "0xl";
    if (is_writer)
      *fmt += "x";
    else
      *fmt += "i";
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

string BPFModule::make_reader(Module *mod, Type *type) {
  auto fn_it = readers_.find(type);
  if (fn_it != readers_.end())
    return fn_it->second;

  // int read(const char *in, Type *out) {
  //   int n = sscanf(in, "{ %i ... }", &out->field1, ...);
  //   if (n != num_fields) return -1;
  //   return 0;
  // }

  IRBuilder<> B(*ctx_);

  string name = "reader" + std::to_string(readers_.size());
  vector<Type *> fn_args({B.getInt8PtrTy(), PointerType::getUnqual(type)});
  FunctionType *fn_type = FunctionType::get(B.getInt32Ty(), fn_args, /*isVarArg=*/false);
  Function *fn =
      Function::Create(fn_type, GlobalValue::ExternalLinkage, name, mod);
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

  readers_[type] = name;
  return name;
}

string BPFModule::make_writer(Module *mod, Type *type) {
  auto fn_it = writers_.find(type);
  if (fn_it != writers_.end())
    return fn_it->second;

  // int write(int len, char *out, Type *in) {
  //   return snprintf(out, len, "{ %i ... }", out->field1, ...);
  // }

  IRBuilder<> B(*ctx_);

  string name = "writer" + std::to_string(writers_.size());
  vector<Type *> fn_args({B.getInt8PtrTy(), B.getInt64Ty(), PointerType::getUnqual(type)});
  FunctionType *fn_type = FunctionType::get(B.getInt32Ty(), fn_args, /*isVarArg=*/false);
  Function *fn =
      Function::Create(fn_type, GlobalValue::ExternalLinkage, name, mod);
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

  writers_[type] = name;
  return name;
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
int BPFModule::load_cfile(const string &file, bool in_memory, const char *cflags[], int ncflags) {
  clang_loader_ = ebpf::make_unique<ClangLoader>(&*ctx_, flags_);
  if (clang_loader_->parse(&mod_, *ts_, file, in_memory, cflags, ncflags, id_, maps_ns_))
    return -1;
  return 0;
}

// NOTE: this is a duplicate of the above, but planning to deprecate if we
// settle on clang as the frontend

// Load in a pre-built list of functions into the initial Module object, then
// build an ExecutionEngine.
int BPFModule::load_includes(const string &text) {
  clang_loader_ = ebpf::make_unique<ClangLoader>(&*ctx_, flags_);
  if (clang_loader_->parse(&mod_, *ts_, text, true, nullptr, 0, "", ""))
    return -1;
  return 0;
}

int BPFModule::annotate() {
  for (auto fn = mod_->getFunctionList().begin(); fn != mod_->getFunctionList().end(); ++fn)
    if (!fn->hasFnAttribute(Attribute::NoInline))
      fn->addFnAttr(Attribute::AlwaysInline);

  // separate module to hold the reader functions
  auto m = ebpf::make_unique<Module>("sscanf", *ctx_);

  size_t id = 0;
  Path path({id_});
  for (auto it = ts_->lower_bound(path), up = ts_->upper_bound(path); it != up; ++it) {
    TableDesc &table = it->second;
    tables_.push_back(&it->second);
    table_names_[table.name] = id++;
    GlobalValue *gvar = mod_->getNamedValue(table.name);
    if (!gvar) continue;
    if (PointerType *pt = dyn_cast<PointerType>(gvar->getType())) {
      if (StructType *st = dyn_cast<StructType>(pt->getElementType())) {
        if (st->getNumElements() < 2) continue;
        Type *key_type = st->elements()[0];
        Type *leaf_type = st->elements()[1];

        using std::placeholders::_1;
        using std::placeholders::_2;
        using std::placeholders::_3;
        table.key_sscanf = std::bind(&BPFModule::sscanf, this,
                                     make_reader(&*m, key_type), _1, _2);
        table.leaf_sscanf = std::bind(&BPFModule::sscanf, this,
                                      make_reader(&*m, leaf_type), _1, _2);
        table.key_snprintf = std::bind(&BPFModule::snprintf, this,
                                       make_writer(&*m, key_type), _1, _2, _3);
        table.leaf_snprintf =
            std::bind(&BPFModule::snprintf, this, make_writer(&*m, leaf_type),
                      _1, _2, _3);
      }
    }
  }

  rw_engine_ = finalize_rw(move(m));
  if (!rw_engine_)
    return -1;
  return 0;
}

StatusTuple BPFModule::sscanf(string fn_name, const char *str, void *val) {
  auto fn =
      (int (*)(const char *, void *))rw_engine_->getFunctionAddress(fn_name);
  if (!fn)
    return StatusTuple(-1, "sscanf not available");
  int rc = fn(str, val);
  if (rc < 0)
    return StatusTuple(rc, "error in sscanf: %s", std::strerror(errno));
  return StatusTuple(rc);
}

StatusTuple BPFModule::snprintf(string fn_name, char *str, size_t sz,
                                const void *val) {
  auto fn = (int (*)(char *, size_t,
                     const void *))rw_engine_->getFunctionAddress(fn_name);
  if (!fn)
    return StatusTuple(-1, "snprintf not available");
  int rc = fn(str, sz, val);
  if (rc < 0)
    return StatusTuple(rc, "error in snprintf: %s", std::strerror(errno));
  if ((size_t)rc == sz)
    return StatusTuple(-1, "buffer of size %zd too small", sz);
  return StatusTuple(0);
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
  /*
   * llvm < 4.0 needs
   * PM.add(createAlwaysInlinerPass());
   * llvm >= 4.0 needs
   * PM.add(createAlwaysInlinerLegacyPass());
   * use below 'stable' workaround
   */
  LLVMAddAlwaysInlinerPass(reinterpret_cast<LLVMPassManagerRef>(&PM));
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
  builder.setMCJITMemoryManager(ebpf::make_unique<MyMemoryManager>(&sections_));
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

size_t BPFModule::num_tables() const { return tables_.size(); }

size_t BPFModule::table_id(const string &name) const {
  auto it = table_names_.find(name);
  if (it == table_names_.end()) return ~0ull;
  return it->second;
}

int BPFModule::table_fd(const string &name) const {
  return table_fd(table_id(name));
}

int BPFModule::table_fd(size_t id) const {
  if (id >= tables_.size())
    return -1;
  return tables_[id]->fd;
}

int BPFModule::table_type(const string &name) const {
  return table_type(table_id(name));
}

int BPFModule::table_type(size_t id) const {
  if (id >= tables_.size())
    return -1;
  return tables_[id]->type;
}

size_t BPFModule::table_max_entries(const string &name) const {
  return table_max_entries(table_id(name));
}

size_t BPFModule::table_max_entries(size_t id) const {
  if (id >= tables_.size())
    return 0;
  return tables_[id]->max_entries;
}

int BPFModule::table_flags(const string &name) const {
  return table_flags(table_id(name));
}

int BPFModule::table_flags(size_t id) const {
  if (id >= tables_.size())
    return -1;
  return tables_[id]->flags;
}

const char * BPFModule::table_name(size_t id) const {
  if (id >= tables_.size())
    return nullptr;
  return tables_[id]->name.c_str();
}

const char * BPFModule::table_key_desc(size_t id) const {
  if (b_loader_) return nullptr;
  if (id >= tables_.size())
    return nullptr;
  return tables_[id]->key_desc.c_str();
}

const char * BPFModule::table_key_desc(const string &name) const {
  return table_key_desc(table_id(name));
}

const char * BPFModule::table_leaf_desc(size_t id) const {
  if (b_loader_) return nullptr;
  if (id >= tables_.size())
    return nullptr;
  return tables_[id]->leaf_desc.c_str();
}

const char * BPFModule::table_leaf_desc(const string &name) const {
  return table_leaf_desc(table_id(name));
}
size_t BPFModule::table_key_size(size_t id) const {
  if (id >= tables_.size())
    return 0;
  return tables_[id]->key_size;
}
size_t BPFModule::table_key_size(const string &name) const {
  return table_key_size(table_id(name));
}

size_t BPFModule::table_leaf_size(size_t id) const {
  if (id >= tables_.size())
    return 0;
  return tables_[id]->leaf_size;
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
  if (id >= tables_.size())
    return -1;
  const TableDesc &desc = *tables_[id];
  StatusTuple rc = desc.key_snprintf(buf, buflen, key);
  if (rc.code() < 0) {
    fprintf(stderr, "%s\n", rc.msg().c_str());
    return -1;
  }
  return 0;
}

int BPFModule::table_leaf_printf(size_t id, char *buf, size_t buflen, const void *leaf) {
  if (id >= tables_.size())
    return -1;
  const TableDesc &desc = *tables_[id];
  StatusTuple rc = desc.leaf_snprintf(buf, buflen, leaf);
  if (rc.code() < 0) {
    fprintf(stderr, "%s\n", rc.msg().c_str());
    return -1;
  }
  return 0;
}

int BPFModule::table_key_scanf(size_t id, const char *key_str, void *key) {
  if (id >= tables_.size())
    return -1;
  const TableDesc &desc = *tables_[id];
  StatusTuple rc = desc.key_sscanf(key_str, key);
  if (rc.code() < 0) {
    fprintf(stderr, "%s\n", rc.msg().c_str());
    return -1;
  }
  return 0;
}

int BPFModule::table_leaf_scanf(size_t id, const char *leaf_str, void *leaf) {
  if (id >= tables_.size())
    return -1;
  const TableDesc &desc = *tables_[id];
  StatusTuple rc = desc.leaf_sscanf(leaf_str, leaf);
  if (rc.code() < 0) {
    fprintf(stderr, "%s\n", rc.msg().c_str());
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
  auto helpers_h = ExportedFiles::headers().find("/virtual/include/bcc/helpers.h");
  if (helpers_h == ExportedFiles::headers().end()) {
    fprintf(stderr, "Internal error: missing bcc/helpers.h");
    return -1;
  }
  if (int rc = load_includes(helpers_h->second))
    return rc;

  b_loader_.reset(new BLoader(flags_));
  if (int rc = b_loader_->parse(&*mod_, filename, proto_filename, *ts_, id_, maps_ns_))
    return rc;
  if (int rc = annotate())
    return rc;
  if (int rc = finalize())
    return rc;
  return 0;
}

// load a C file
int BPFModule::load_c(const string &filename, const char *cflags[], int ncflags) {
  if (!sections_.empty()) {
    fprintf(stderr, "Program already initialized\n");
    return -1;
  }
  if (filename.empty()) {
    fprintf(stderr, "Invalid filename\n");
    return -1;
  }
  if (int rc = load_cfile(filename, false, cflags, ncflags))
    return rc;
  if (int rc = annotate())
    return rc;
  if (int rc = finalize())
    return rc;
  return 0;
}

// load a C text string
int BPFModule::load_string(const string &text, const char *cflags[], int ncflags) {
  if (!sections_.empty()) {
    fprintf(stderr, "Program already initialized\n");
    return -1;
  }
  if (int rc = load_cfile(text, true, cflags, ncflags))
    return rc;
  if (int rc = annotate())
    return rc;

  if (int rc = finalize())
    return rc;
  return 0;
}

} // namespace ebpf
