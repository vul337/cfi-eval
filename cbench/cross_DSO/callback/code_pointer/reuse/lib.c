#include "lib.h"
#include <stdio.h>

__attribute__((visibility("default"))) void Callback(struct FuncPtr fptr,
                                                     int arg) {
  printf("fptr is %p\n",fptr);
	printf("Calling a function:\n");
  fptr.correct_func[arg](arg, arg);
}
