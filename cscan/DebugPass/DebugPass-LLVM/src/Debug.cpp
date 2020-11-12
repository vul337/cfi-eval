#define DEBUG_TYPE "DEBUG"
#include "llvm/ADT/Statistic.h"
//#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/IRPrintingPasses.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Pass.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include <sstream>
#include <unordered_set>
//#include "llvm/Passes/PassBuilder.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/CallGraphSCCPass.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Support/Debug.h"
#include <string>
using namespace std;
using namespace llvm;
namespace {
struct Debug : public FunctionPass {
  static char ID; // Pass identification, replacement for typeid
  std::unordered_set<Instruction *> instrumented;

  Debug() : FunctionPass(ID) {}

  void doInstrument(Instruction *pre, Instruction *call) {
    /*
      errs() << "\"" << *pre << "\""
             << " -> "
             << "\"" << *call << "\""
             << ";\n";
    */
    if (instrumented.find(pre->getNextNode()) != instrumented.end()) {
      errs() << "dup detected\n";
      return;
    }

    llvm::IRBuilder<> builder_icall(pre);
    builder_icall.SetInsertPoint(pre->getNextNode());
    auto debugFunc = Intrinsic::getDeclaration(
        call->getParent()->getParent()->getParent(), Intrinsic::debugtrap);
    auto debugCall = builder_icall.CreateCall(debugFunc, {});
    auto instrument_loc = pre->getNextNode();
    instrumented.insert(instrument_loc);
  }

  bool runOnFunction(Function &F) override {
    Function::iterator FB, FE;
    FB = F.begin();
    FE = F.end();
    for (FB = F.begin(), FE = F.end(); FB != FE; FB++) {
      BasicBlock *B = &*FB;
      BasicBlock::iterator BB, BE;

      for (BB = FB->begin(), BE = FB->end(); BB != BE; BB++) {
        Instruction *I = &*BB;

        // found: call site
        if (CallInst *callInst = dyn_cast<CallInst>(I)) {
          Function *calledFunc = callInst->getCalledFunction();
          // found: indirect call site
          if (calledFunc == NULL) {
            Value *v = callInst->getCalledValue();

            if (auto pre = dyn_cast<Instruction>(v)) {
              bool isvptr = false;
              for (Use &U : pre->operands()) {
                v = U.get();
                if (auto Inst = dyn_cast<GetElementPtrInst>(v)) {
                  for (Use &U : Inst->operands()) {
                    v = U.get();
                    if (auto vptr = dyn_cast<LoadInst>(v)) {
                      if (vptr->getMetadata("vtable-ptr")) {
                        doInstrument(vptr, callInst);
                        isvptr = true;
                      }
                      // If you don't want to patch related functions, you can
                      // use this method.
                      /*
                         string::size_type idx;
                         idx=vptr->getName().str().find("vtable");
                         if(idx != string::npos){
                          //pre=vptr;
                          doInstrument(vptr, callInst,22);
                          errs()<<"find it:::"<<*vptr<<"\n";
                          isvptr = true;
                      }*/
                    }
                  }
                }
              }
              if (!isvptr)
                doInstrument(pre, callInst);
            }
          }
        } else if (InvokeInst *invokeInst = dyn_cast<InvokeInst>(I)) {
          Function *calledFunc = invokeInst->getCalledFunction();
          // found: indirect call site
          if (calledFunc == NULL) {
            Value *v = invokeInst->getCalledValue();

            if (auto pre = dyn_cast<Instruction>(v)) {
              bool isvptr = false;
              for (Use &U : pre->operands()) {
                v = U.get();
                if (auto Inst = dyn_cast<GetElementPtrInst>(v)) {
                  for (Use &U : Inst->operands()) {
                    v = U.get();
                    if (auto vptr = dyn_cast<LoadInst>(v)) {
                      if (vptr->getMetadata("vtable-ptr")) {
                        doInstrument(vptr, invokeInst);
                        isvptr = true;
                      }
                      // If you don't want to patch related functions, you can
                      // use this method.
                      /*
                         string::size_type idx;
                         idx=vptr->getName().str().find("vtable");
                         if(idx != string::npos){
                          //pre=vptr;
                          doInstrument(vptr, callInst,22);
                          errs()<<"find it:::"<<*vptr<<"\n";
                          isvptr = true;
                      }*/
                    }
                  }
                }
              }
              if (!isvptr)
                doInstrument(pre, invokeInst);
            }
          }
        } else if (CallBrInst *callbrInst = dyn_cast<CallBrInst>(I)) {
          Function *calledFunc = callbrInst->getCalledFunction();
          // found: indirect call site
          if (calledFunc == NULL) {
            Value *v = callbrInst->getCalledValue();

            if (auto pre = dyn_cast<Instruction>(v)) {
              doInstrument(pre, callbrInst);
            }
          }
        }
      }
    }
    return false;
  }
};
} // namespace

char Debug::ID = 0;
static RegisterPass<Debug> X("Debug", "debug Pass");

static void registerDebug(const PassManagerBuilder &,
                          legacy::PassManagerBase &PM) {
  PM.add(new Debug());
}
static RegisterStandardPasses
    RegisterDebug(PassManagerBuilder::EP_OptimizerLast, registerDebug);

static RegisterStandardPasses
    RegisterDebug0(PassManagerBuilder::EP_EnabledOnOptLevel0, registerDebug);
