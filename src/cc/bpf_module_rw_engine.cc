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
#include <map>
#include <string>
#include <vector>

#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/TargetSelect.h>

#include "common.h"
#include "bpf_module.h"
#include "table_storage.h"

namespace ebpf {

using std::map;
using std::move;
using std::string;
using std::unique_ptr;
using std::vector;
using namespace llvm;

bool bpf_module_rw_engine_enabled(void) {
  return true;
}

void BPFModule::initialize_rw_engine() {
  InitializeNativeTarget();
  InitializeNativeTargetAsmPrinter();
}

void BPFModule::cleanup_rw_engine() {
  rw_engine_.reset();
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

static void finish_sscanf(IRBuilder<> &B, vector<Value *> *args, string *fmt,
                          const map<string, Value *> &locals, bool exact_args) {
  // fmt += "%n";
  // int nread = 0;
  // int n = sscanf(s, fmt, args..., &nread);
  // if (n < 0) return -1;
  // s = &s[nread];
  Value *sptr = locals.at("sptr");
  Value *nread = locals.at("nread");
  Function *cur_fn = B.GetInsertBlock()->getParent();
  Function *sscanf_fn = B.GetInsertBlock()->getModule()->getFunction("sscanf");
  *fmt += "%n";
  B.CreateStore(B.getInt32(0), nread);
  GlobalVariable *fmt_gvar = B.CreateGlobalString(*fmt, "fmt");
  (*args)[1] = B.CreateInBoundsGEP(fmt_gvar, {B.getInt64(0), B.getInt64(0)});
  (*args)[0] = B.CreateLoad(sptr);
  args->push_back(nread);
  CallInst *call = B.CreateCall(sscanf_fn, *args);
  call->setTailCall(true);

  BasicBlock *label_true = BasicBlock::Create(B.getContext(), "", cur_fn);
  BasicBlock *label_false = BasicBlock::Create(B.getContext(), "", cur_fn);

  // exact_args means fail if don't consume exact number of "%" inputs
  // exact_args is disabled for string parsing (empty case)
  Value *cond = exact_args ? B.CreateICmpNE(call, B.getInt32(args->size() - 3))
                           : B.CreateICmpSLT(call, B.getInt32(0));
  B.CreateCondBr(cond, label_true, label_false);

  B.SetInsertPoint(label_true);
  B.CreateRet(B.getInt32(-1));

  B.SetInsertPoint(label_false);
  // s = &s[nread];
  B.CreateStore(
      B.CreateInBoundsGEP(B.CreateLoad(sptr), B.CreateLoad(nread, true)), sptr);

  args->resize(2);
  fmt->clear();
}

// recursive helper to capture the arguments
static void parse_type(IRBuilder<> &B, vector<Value *> *args, string *fmt,
                       Type *type, Value *out,
                       const map<string, Value *> &locals, bool is_writer) {
  if (StructType *st = dyn_cast<StructType>(type)) {
    *fmt += "{ ";
    unsigned idx = 0;
    for (auto field : st->elements()) {
      parse_type(B, args, fmt, field, B.CreateStructGEP(type, out, idx++),
                 locals, is_writer);
      *fmt += " ";
    }
    *fmt += "}";
  } else if (ArrayType *at = dyn_cast<ArrayType>(type)) {
    if (at->getElementType() == B.getInt8Ty()) {
      // treat i8[] as a char string instead of as an array of u8's
      if (is_writer) {
        *fmt += "\"%s\"";
        args->push_back(out);
      } else {
        // When reading strings, scanf doesn't support empty "", so we need to
        // break this up into multiple scanf calls. To understand it, let's take
        // an example:
        // struct Event {
        //   u32 a;
        //   struct {
        //     char x[64];
        //     int y;
        //   } b[2];
        //   u32 c;
        // };
        // The writer string would look like:
        //  "{ 0x%x [ { \"%s\" 0x%x } { \"%s\" 0x%x } ] 0x%x }"
        // But the reader string needs to restart at each \"\".
        //  reader0(const char *s, struct Event *val) {
        //    int nread, rc;
        //    nread = 0;
        //    rc = sscanf(s, "{ %i [ { \"%n", &val->a, &nread);
        //    if (rc != 1) return -1;
        //    s += nread; nread = 0;
        //    rc = sscanf(s, "%[^\"]%n", &val->b[0].x, &nread);
        //    if (rc < 0) return -1;
        //    s += nread; nread = 0;
        //    rc = sscanf(s, "\" %i } { \"%n", &val->b[0].y, &nread);
        //    if (rc != 1) return -1;
        //    s += nread; nread = 0;
        //    rc = sscanf(s, "%[^\"]%n", &val->b[1].x, &nread);
        //    if (rc < 0) return -1;
        //    s += nread; nread = 0;
        //    rc = sscanf(s, "\" %i } ] %i }%n", &val->b[1].y, &val->c, &nread);
        //    if (rc != 2) return -1;
        //    s += nread; nread = 0;
        //    return 0;
        //  }
        *fmt += "\"";
        finish_sscanf(B, args, fmt, locals, true);

        *fmt = "%[^\"]";
        args->push_back(out);
        finish_sscanf(B, args, fmt, locals, false);

        *fmt = "\"";
      }
    } else {
      *fmt += "[ ";
      for (size_t i = 0; i < at->getNumElements(); ++i) {
        parse_type(B, args, fmt, at->getElementType(),
                   B.CreateStructGEP(type, out, i), locals, is_writer);
        *fmt += " ";
      }
      *fmt += "]";
    }
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

// make_reader generates a dynamic function in the instruction set of the host
// (not bpf) that is able to convert c-strings in the pretty-print format of
// make_writer back into binary representations. The encoding of the string
// takes the llvm ir structure format, which closely maps the c structure but
// not exactly (no support for unions for instance).
// The general algorithm is:
//  pod types (u8..u64)                <= %i
//  array types
//   u8[]  no nested quotes :(         <= "..."
//   !u8[]                             <= [ %i %i ... ]
//  struct types
//   struct { u8 a; u64 b; }           <= { %i %i }
//  nesting is supported
//   struct { struct { u8 a[]; }; }    <= { "" }
//   struct { struct { u64 a[]; }; }   <= { [ %i %i .. ] }
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

  FunctionType *sscanf_fn_type = FunctionType::get(
      B.getInt32Ty(), {B.getInt8PtrTy(), B.getInt8PtrTy()}, /*isVarArg=*/true);
  Function *sscanf_fn = mod->getFunction("sscanf");
  if (!sscanf_fn) {
    sscanf_fn = Function::Create(sscanf_fn_type, GlobalValue::ExternalLinkage,
                                 "sscanf", mod);
    sscanf_fn->setCallingConv(CallingConv::C);
    sscanf_fn->addFnAttr(Attribute::NoUnwind);
  }

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
  B.SetInsertPoint(label_entry);

  Value *nread = B.CreateAlloca(B.getInt32Ty());
  Value *sptr = B.CreateAlloca(B.getInt8PtrTy());
  map<string, Value *> locals{{"nread", nread}, {"sptr", sptr}};
  B.CreateStore(arg_in, sptr);
  vector<Value *> args({nullptr, nullptr});
  string fmt;
  parse_type(B, &args, &fmt, type, arg_out, locals, false);

  if (0)
    debug_printf(mod, B, "%p %p\n", vector<Value *>({arg_in, arg_out}));

  finish_sscanf(B, &args, &fmt, locals, true);

  B.CreateRet(B.getInt32(0));

  readers_[type] = name;
  return name;
}

// make_writer generates a dynamic function in the instruction set of the host
// (not bpf) that is able to pretty-print key/leaf entries as a c-string. The
// encoding of the string takes the llvm ir structure format, which closely maps
// the c structure but not exactly (no support for unions for instance).
// The general algorithm is:
//  pod types (u8..u64)                => 0x%x
//  array types
//   u8[]                              => "..."
//   !u8[]                             => [ 0x%x 0x%x ... ]
//  struct types
//   struct { u8 a; u64 b; }           => { 0x%x 0x%x }
//  nesting is supported
//   struct { struct { u8 a[]; }; }    => { "" }
//   struct { struct { u64 a[]; }; }   => { [ 0x%x 0x%x .. ] }
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

  map<string, Value *> locals{
      {"nread", B.CreateAlloca(B.getInt64Ty())},
  };
  vector<Value *> args({arg_out, B.CreateZExt(arg_len, B.getInt64Ty()), nullptr});
  string fmt;
  parse_type(B, &args, &fmt, type, arg_in, locals, true);

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
#if LLVM_MAJOR_VERSION <= 11
  builder.setUseOrcMCJITReplacement(false);
#endif
  auto engine = unique_ptr<ExecutionEngine>(builder.create());
  if (!engine)
    fprintf(stderr, "Could not create ExecutionEngine: %s\n", err.c_str());
  return engine;
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
  if (!rw_engine_enabled_)
    return StatusTuple(-1, "rw_engine not enabled");
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
  if (!rw_engine_enabled_)
    return StatusTuple(-1, "rw_engine not enabled");
  auto fn = (int (*)(char *, size_t,
                     const void *))rw_engine_->getFunctionAddress(fn_name);
  if (!fn)
    return StatusTuple(-1, "snprintf not available");
  int rc = fn(str, sz, val);
  if (rc < 0)
    return StatusTuple(rc, "error in snprintf: %s", std::strerror(errno));
  if ((size_t)rc == sz)
    return StatusTuple(-1, "buffer of size %zd too small", sz);
  return StatusTuple::OK();
}

} // namespace ebpf
