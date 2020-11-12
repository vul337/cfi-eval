# Debug about MCFI/PICFI

Because MCFI/PICFI uses backend pass to process indirect transfer instructions, 
we patched the backend pass of MCFI.


```
--- X86MCFI.cpp	2020-11-11 23:32:29.402033738 +0800
+++ compiler/llvm-3.5.0.src/lib/Target/X86/X86MCFI.cpp	2020-11-11 23:38:12.874030088 +0800
@@ -798,6 +798,8 @@ void MCFI::MCFIx64IndirectCall(MachineFu
         auto &MIB = BuildMI(*DefMBB, DefI, DL, TII->get(X86::MOV32rm))
           .addReg(getX86SubSuperRegister(TargetReg, MVT::i32, true), RegState::Define);

+  BuildMI(*DefMBB, DefI, DL, TII->get(X86::INT3));//dora added
+
         for (auto idx = 1; idx < 6; idx++) // 5 machineoperands
           MIB.addOperand(DefI->getOperand(idx));
         DefMBB->erase(DefI);
@@ -810,6 +812,8 @@ void MCFI::MCFIx64IndirectCall(MachineFu
       BuildMI(*MBB, MI, DL, TII->get(X86::MOV32rr))
         .addReg(getX86SubSuperRegister(TargetReg, MVT::i32, true), RegState::Define)
         .addReg(getX86SubSuperRegister(TargetReg, MVT::i32, true), RegState::Undef);
+
+  BuildMI(*MBB,MI, DL, TII->get(X86::INT3));//dora added
     }
   } else { // JMP64m or CALL64m or TAILJMPm64
     TargetReg = *ScratchRegs.begin();
@@ -818,6 +822,8 @@ void MCFI::MCFIx64IndirectCall(MachineFu
     auto &MIB = BuildMI(*MBB, MI, DL, TII->get(X86::MOV32rm))
       .addReg(getX86SubSuperRegister(TargetReg, MVT::i32, true), RegState::Define);

+  BuildMI(*MBB,MI, DL, TII->get(X86::INT3));//dora added
+
     /* testing-use
     auto &MIB = BuildMI(*MBB, MI, DL, TII->get(X86::MOV64rm))
       .addReg(TargetReg, RegState::Define);
```

## Note
The clang of MCFI/PICFI compiles dynamic libraries such as libcxx. 
However, we only check the indirect transfer instructions in the corresponding program, 
which is consistent with the handle of other CFI solutions. 
Therefore, our patch should be applied after the MCFI/PICFI toolchain is generated.