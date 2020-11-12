# Debug Pass

If the LLVM version used by the CFI mechanism is 3.x, 
users need to use the corresponding method to add the pass and need to change some `#include` lines.

There is no `CallBrInst` in the lower version of llvm. 
If the user uses the lower version of llvm, the related code may need to be deleted.