#include "lib.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int SameTypeFunc(int a, int b) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}

void DiffRetFunc(int a, int b) { printf("In %s \n", __FUNCTION__); }

int DiffArgFunc(int a, float b) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}

int MoreArgFunc(int a, int b, int c) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}

int LessArgFunc(int a) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}

int VoidArgFunc(void) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}

int Foo(int a, int b) {
  printf("In %s\n", __FUNCTION__);
  return 0;
}

// the struct aligns the function pointer arrays
// so indexing past the end will reliably call working function pointers
static struct FuncPtr fptr1 = {
    .correct_func = {Foo},
    .same_type_func = {SameTypeFunc},
    .diff_arg_func = {DiffArgFunc},
    .diff_ret_func = {DiffRetFunc},
    .more_arg_func = {MoreArgFunc},
    .less_arg_func = {LessArgFunc},
    .void_arg_func = {VoidArgFunc},
};

int main(int argc, const char *argv[]) {
  if (argc != 2) {
    printf("Usage: %s <option>\n", argv[0]);
    printf("Option values:\n");
    printf("0: the correct function");
    printf("1-6: out of bound access inside the same object");
    printf("\tthe correct function: %p\n", (void *)fptr1.correct_func);

    return 1;
  }

  int idx = argv[1][0] - '0';
  Callback(fptr1, idx);

  return 0;
}
