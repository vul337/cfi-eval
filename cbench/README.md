# CBench: Check Your CFI's Failed Protections

This is the CBench part of source code of our CCS'20 paper "Finding Cracks in
Shields: On the Security of Control Flow Integrity Mechanisms".

## How to use
CBench is a sanity check to verify whether the CFI mechanism is effective in
common classic attack scenarios. CBench first provides a series of vulnerable
programs, and the original executable files (x86_64) without CFI. Related
scripts for exploiting the vulnerability are also provided for reference.

## Notes
Binaries protected by CFIs may differ from the original ones, thus the exploits
needs to be adjusted too.

Furthermore, we would like to emphasize that CBench is a sanity check. The
results can reflect the strength of CFIs, but they are not precise measurements.

## List of Attacks
See Table A5 in our paper for details.

```
.
├── assembly_support
│   ├── aarch64_inline_icall.c
│   ├── aarch64_inline_ijmp.c
│   ├── x86_inline_icall.c
│   └── x86_inline_ijmp.c
├── cross_DSO
│   ├── callback
│   │   ├── code_pointer
│   │   │   ├── overwrite
│   │   │   └── reuse
│   │   └── object
│   │       ├── injection
│   │       └── reuse
│   ├── code_pointer
│   │   ├── overwrite
│   │   └── reuse
│   ├── object
│   │   ├── injection
│   │   └── reuse
│   └── return_address
├── indirect_call
│   ├── ptr_OOB.c
│   ├── ptr_overwrite.c
├── indirect_jump
│   ├── setjmp.c
│   ├── tailcall_overwrite.c
│   ├── tailcall_reuse_multithreading.c
│   └── tailcall_reuse_single_phread.c
├── return_address
│   └── ret_injection.c
├── type_confusion
│   ├── cfi_function.c
│   ├── cfi_object.cpp
│   └── cfi_object_function.cpp
├── vDSO_test
│   └── vdso_test.c
└── virtual_call
    ├── coop.cpp
    ├── vtable_injection_overflow.cpp
    ├── vtable_injection_uaf.cpp
    └── vtable_reuse_uaf.cpp
 ```
