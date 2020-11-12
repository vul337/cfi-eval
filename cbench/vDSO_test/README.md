# vDSO test

1. If a CFI scheme does not support Cross-DSO protection, we consider it has no support for vDSO protection.

2. If a CFI mechanism that supports Cross-DSO protection but requires instrumentation for the target dso, 
it is also considered that the scheme cannot support vDSO protection. 
(We assume that vDSO will not be instrumented unless some special processing is done.)

3. If a scheme supports Cross-DSO protection and does not require additional instrumentation for the target DSO, 
we believe that it should also support vDSO protection, and then perform the test.

Currently, only LOCKDOWN meets the above requirements, so we only provide 32-bit binary and output logs when LOCKDOWN is used.
