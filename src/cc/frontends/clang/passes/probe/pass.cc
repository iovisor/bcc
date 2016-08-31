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

class ProbeConverter : public FunctionPass {
 public:
  static char ID;
  ProbeConverter() : FunctionPass(ID) {
    initializeProbeConverterPass(*PassRegistry::getPassRegistry());
  }
  ~ProbeConverter() override {}
  bool runOnFunction(Function &F) override {
    //const TargetLibraryInfo *TLI = &getAnalysis<TargetLibraryInfoWrapperPass>().getTLI();
    DominatorTree *DT = &getAnalysis<DominatorTreeWrapperPass>().getDomTree();
    //MemoryDependenceResults *MD = &getAnalysis<MemoryDependenceWrapperPass>().getMemDep();
    AliasAnalysis *AA = &getAnalysis<AAResultsWrapperPass>().getAAResults();
    BasicBlock *entry = &F.getEntryBlock();
    Module *mod = entry->getModule();
    const DataLayout &DL = mod->getDataLayout();
    IRBuilder<TargetFolder> Builder(entry->getContext(), TargetFolder(mod->getDataLayout()));

    AliasSetTracker tracker(*AA);
    for (BasicBlock &BB: F)
      for (Instruction &I : BB)
        tracker.add(&I);

    errs() << "ProbeConverter: "; errs().write_escaped(F.getName()) << "\n";
    if (F.getName() != "do_request")
      return false;

    DenseMap<Value *, bool> values;
    errs() << " Alias Sets:\n";
    for (const AliasSet &AS : tracker) {
      AS.print(errs());
      bool onstack = false;
      for (auto &I : AS)
        onstack |= isa<AllocaInst>(I.getValue());
      if (!onstack) {
        for (auto &I : AS)
          values[I.getValue()] = true;
      }
    }

    errs() << " Basic Blocks: \n";
    //if (!F.isDeclaration() && F.hasFnAttribute(Attribute::AlwaysInline))
    //  return false;
    for (BasicBlock &BB : F) {
      if (!DT->isReachableFromEntry(&BB))
        continue;
      for (Instruction &I : BB) {
        I.dump();
        if (!I.mayReadFromMemory())
          continue;
        if (auto LD = dyn_cast<LoadInst>(&I)) {
          Value *V = LD->getPointerOperand();
          if (values.find(V) == values.end())
            continue;
          FunctionType *probe_fn_ty = FunctionType::get(Builder.getInt32Ty(),
                                                        vector<Type *>({Builder.getInt8PtrTy(),
                                                                       Builder.getInt64Ty(),
                                                                       Builder.getInt8PtrTy()}),
                                                        false);
          //Function *probe_fn = mod->getFunction("bpf_probe_read");
          //if (!probe_fn)
          //  probe_fn = Function::Create(probe_fn_ty, GlobalValue::ExternalLinkage, "bpf_probe_read", mod);
          //probe_fn->onlyAccessesArgMemory();
          //probe_fn->setDoesNotCapture(0);
          //probe_fn->setDoesNotCapture(2);
          //probe_fn->setOnlyReadsMemory(2);

          Builder.SetInsertPoint(&entry->front());
          AllocaInst *dst = Builder.CreateAlloca(LD->getType(), nullptr, "");
          Builder.SetInsertPoint(LD);
          Value *probe_fn = Builder.CreateIntToPtr(Builder.getInt64(BPF_FUNC_probe_read),
                                                   PointerType::getUnqual(probe_fn_ty));
          errs() << "dst = "; dst->print(errs()); errs() << "\n";
          Value *dst_sizeof = Builder.getInt64(DL.getTypeSizeInBits(LD->getType()) >> 3);
          errs() << "sizeof(dst) = "; dst_sizeof->print(errs()); errs() << "\n";
          errs() << "V = "; V->print(errs()); errs() << "\n";
          vector<Value *> args({Builder.CreateBitCast(dst, Builder.getInt8PtrTy()),
                               dst_sizeof,
                               Builder.CreateBitCast(V, Builder.getInt8PtrTy())});
          Builder.CreateCall(probe_fn, args);
          LoadInst *dst_load = Builder.CreateLoad(dst);
          errs() << dst_load << " "; dst_load->print(errs()); errs() << "\n";
          LD->replaceAllUsesWith(dst_load);
        }
      }
      errs() << "\n";
    }
    return true;
  }
  void getAnalysisUsage(AnalysisUsage &AU) const {
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
