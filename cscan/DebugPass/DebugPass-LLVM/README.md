# Debug Pass

The check of LLVM-CFI for virtual function calls is to check the virtual table, 
not the corresponding virtual function, 
so our pass for this type of CFI mechanism is partially different.

## patch related function

`clang/lib/CodeGen/CGClass.cpp`

```
llvm::Value *CodeGenFunction::GetVTablePtr(Address This,
                                           llvm::Type *VTableTy,
                                           const CXXRecordDecl *RD) {
  Address VTablePtrSrc = Builder.CreateElementBitCast(This, VTableTy);
  llvm::Instruction *VTable = Builder.CreateLoad(VTablePtrSrc, "vtable");

+  llvm::LLVMContext &C = VTable->getContext();
+  llvm::MDNode *N = llvm::MDNode::get(C, llvm::MDString::get(C, "virtual function pointer"));
+  VTable->setMetadata("vtable-ptr", N);

  TBAAAccessInfo TBAAInfo = CGM.getTBAAVTablePtrAccessInfo(VTableTy);
  CGM.DecorateInstructionWithTBAA(VTable, TBAAInfo);

  if (CGM.getCodeGenOpts().OptimizationLevel > 0 &&
      CGM.getCodeGenOpts().StrictVTablePointers)
    CGM.DecorateInstructionWithInvariantGroup(VTable, RD);

  return VTable;
}
```

`llvm/lib/Transforms/Utils/Local.cpp`

```
void llvm::combineMetadata(Instruction *K, const Instruction *J,
                           ArrayRef<unsigned> KnownIDs) {
.....

  if (auto *JMD = J->getMetadata(LLVMContext::MD_invariant_group))
    if (isa<LoadInst>(K) || isa<StoreInst>(K))
      K->setMetadata(LLVMContext::MD_invariant_group, JMD);

+  K->setMetadata("vtable-ptr", J->getMetadata("vtable-ptr"));
}
```

## Note
There is no `CallBrInst` in the lower version of llvm. 
If the user uses the lower version of llvm, the related code may need to be deleted.