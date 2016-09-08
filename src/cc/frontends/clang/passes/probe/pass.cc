/*
 * Copyright (c) 2016 PLUMgrid, Inc.
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

#include <llvm/Pass.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/GlobalsModRef.h>
#include <llvm/Analysis/MemoryDependenceAnalysis.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Analysis/TargetFolder.h>
#include <llvm/Analysis/AliasSetTracker.h>
#include <llvm/IR/Dominators.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/InlinerPass.h>

#include "frontends/clang/passes/probe/pass.h"
#include "linux/bpf.h"

using std::vector;
using namespace llvm;

namespace llvm {
void initializeProbeConverterPass(PassRegistry&);
}

namespace {

static bool is_onstack(const AliasSet &AS) {
  bool onstack = false;
  for (auto &I : AS)
    onstack |= isa<AllocaInst>(I.getValue());
  return onstack;
}

class ProbeConverter : public FunctionPass {
 private:
  IRBuilder<TargetFolder> *builder;
 public:
  static char ID;
  ProbeConverter() : FunctionPass(ID), builder(nullptr) {
    initializeProbeConverterPass(*PassRegistry::getPassRegistry());
  }
  ~ProbeConverter() override {}
  Value *create_probe(Value *dst, Value *src, Value *sz) {
    FunctionType *probe_fn_ty = FunctionType::get(builder->getVoidTy(),
                                                  vector<Type *>({builder->getInt8PtrTy(),
                                                                 builder->getInt64Ty(),
                                                                 builder->getInt8PtrTy()}),
                                                  false);
    Value *probe_fn = builder->CreateIntToPtr(builder->getInt64(BPF_FUNC_probe_read),
                                              PointerType::getUnqual(probe_fn_ty));
    vector<Value *> args({builder->CreateBitCast(dst, builder->getInt8PtrTy()), sz,
                         builder->CreateBitCast(src, builder->getInt8PtrTy())});
    CallInst *call = builder->CreateCall(probe_fn, args);
    errs() << "\tnew call: ("; call->print(errs()); errs() << "  )\n";
    return call;
  }
  bool runOnFunction(Function &F) override {
    //const TargetLibraryInfo *TLI = &getAnalysis<TargetLibraryInfoWrapperPass>().getTLI();
    DominatorTree *DT = &getAnalysis<DominatorTreeWrapperPass>().getDomTree();
    //MemoryDependenceResults *MD = &getAnalysis<MemoryDependenceWrapperPass>().getMemDep();
    AliasAnalysis *AA = &getAnalysis<AAResultsWrapperPass>().getAAResults();
    BasicBlock *entry = &F.getEntryBlock();
    Module *mod = entry->getModule();
    const DataLayout &DL = mod->getDataLayout();
    IRBuilder<TargetFolder> TheBuilder(entry->getContext(), TargetFolder(mod->getDataLayout()));
    builder = &TheBuilder;

    AliasSetTracker tracker(*AA);
    for (BasicBlock &BB: F)
      for (Instruction &I : BB)
        tracker.add(&I);

    errs() << "ProbeConverter: "; errs().write_escaped(F.getName()) << "\n";

    DenseMap<Value *, bool> is_unknown;
    errs() << " Alias Sets:\n";
    for (const AliasSet &AS : tracker) {
      bool onstack = is_onstack(AS);
      errs() << "onstack:" << onstack << " forward:" << AS.isForwardingAliasSet(); AS.print(errs());
      for (auto &I : AS) {
        is_unknown[I.getValue()] = !onstack;
        if (AS.isForwardingAliasSet())
          errs() << " forwarding: " << I.getValue() << "\n";
        errs() << "\t" << &I;
      }
      if (!AS.empty())
        errs() << "\n";
    }

    //Function *probe_fn = mod->getFunction("bpf_probe_read");
    //if (!probe_fn)
    //  probe_fn = Function::Create(probe_fn_ty, GlobalValue::ExternalLinkage, "bpf_probe_read", mod);
    //probe_fn->onlyAccessesArgMemory();
    //probe_fn->setDoesNotCapture(0);
    //probe_fn->setDoesNotCapture(2);
    //probe_fn->setOnlyReadsMemory(2);
    vector<Instruction *> dead_inst;

    errs() << " Basic Blocks: \n";
    //if (!F.isDeclaration() && F.hasFnAttribute(Attribute::AlwaysInline))
    //  return false;
    for (BasicBlock &BB : F) {
      if (!DT->isReachableFromEntry(&BB))
        continue;
      for (Instruction &I : BB) {
        I.dump();
        //if (!I.mayReadFromMemory())
        //  continue;
        Value *V = nullptr;
        if (auto MT = dyn_cast<MemTransferInst>(&I)) {
          V = MT->getRawSource();
          auto val = is_unknown.find(V);
          if (val != is_unknown.end() && !val->getSecond())
            continue;
          errs() << "\tbuiltin_memxxx: " << tracker.containsUnknown(cast<Instruction>(MT)) << " (";
          V->print(errs());
          errs() << "  ) (";
          MT->getDest()->print(errs());
          errs() << "  )\n";
          builder->SetInsertPoint(&I);
          //I.replaceAllUsesWith(create_probe(MT->getRawDest(), MT->getRawSource(), MT->getLength()));
          create_probe(MT->getDest(), MT->getRawSource(), MT->getLength());
          dead_inst.push_back(&I);
        } else if (auto LD = dyn_cast<LoadInst>(&I)) {
          V = LD->getPointerOperand();
          auto val = is_unknown.find(V);
          if (val == is_unknown.end() || !val->getSecond())
            continue;

          builder->SetInsertPoint(&entry->front());
          AllocaInst *dst = builder->CreateAlloca(I.getType(), nullptr, "");
          builder->SetInsertPoint(&I);
          errs() << "\tnew dst: ("; dst->print(errs()); errs() << "  )\n";
          Value *dst_sizeof = builder->getInt64(DL.getTypeSizeInBits(I.getType()) >> 3);
          create_probe(dst, V, dst_sizeof);
          LoadInst *dst_load = builder->CreateLoad(dst);
          I.replaceAllUsesWith(dst_load);
        }
      }
      errs() << "\n";
    }
    for (auto I : dead_inst)
      I->eraseFromParent();
    return true;
  }
  void getAnalysisUsage(AnalysisUsage &AU) const override {
    //AU.setPreservesCFG();
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<AAResultsWrapperPass>();
    AU.addRequired<MemoryDependenceWrapperPass>();
    AU.addRequired<TargetLibraryInfoWrapperPass>();
    //AU.addPreserved<DominatorTreeWrapperPass>();
    //AU.addPreserved<GlobalsAAWrapperPass>();
    //AU.addPreserved<MemoryDependenceWrapperPass>();
  }
};

}  // namespace <anon>

char ProbeConverter::ID = 0;
INITIALIZE_PASS_BEGIN(ProbeConverter, "probe_converter", "Probe Converter Pass", false, false)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_DEPENDENCY(AAResultsWrapperPass)
INITIALIZE_PASS_DEPENDENCY(GlobalsAAWrapperPass)
INITIALIZE_PASS_DEPENDENCY(MemoryDependenceWrapperPass)
INITIALIZE_PASS_DEPENDENCY(TargetLibraryInfoWrapperPass)
INITIALIZE_PASS_END(ProbeConverter, "probe_converter", "Probe Converter Pass", false, false)

Pass *create_probe_pass() {
  return new ProbeConverter();
}
