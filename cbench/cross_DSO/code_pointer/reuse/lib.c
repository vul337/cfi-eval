#include "lib.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((visibility("default"))) int SameTypeFunc(int a, int b) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}

__attribute__((visibility("default"))) void DiffRetFunc(int a, int b) {
  printf("In %s \n", __FUNCTION__);
}

__attribute__((visibility("default"))) int DiffArgFunc(int a, float b) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}

__attribute__((visibility("default"))) int MoreArgFunc(int a, int b, int c) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}

__attribute__((visibility("default"))) int LessArgFunc(int a) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}

__attribute__((visibility("default"))) int VoidArgFunc(void) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}

__attribute__((visibility("default"))) int VulEntryFunc(int a, int b) {
  __asm__ volatile("nop\n"
                   "nop\n"
                   "nop\n"
                   "nop\n"
                   "nop\n"
                   "nop\n"
                   "nop\n"
                   "nop\n"
                   "nop\n"
                   "nop\n");
  printf("In %s\n", __FUNCTION__);
  exit(0);
}

__attribute__((visibility("default"))) int Foo(int a, int b) {
  printf("In %s\n", __FUNCTION__);
}

typedef int (*Fptr)(int, int);
typedef void (*DiffRetFptr)(int, int);
typedef int (*DiffArgFptr)(int, float);
typedef int (*MoreArgFptr)(int, int, int);
typedef int (*LessArgFptr)(int);
typedef int (*VoidArgFptr)(void);

Fptr ptr_array[1] = {Foo};
Fptr same_type_array[1] = {SameTypeFunc};
DiffRetFptr diff_ret_array[1] = {DiffRetFunc};
DiffArgFptr diff_arg_array[1] = {DiffArgFunc};
MoreArgFptr more_arg_array[1] = {MoreArgFunc};
LessArgFptr less_arg_array[1] = {LessArgFunc};
VoidArgFptr void_arg_array[1] = {VoidArgFunc};
Fptr vul_entry_array[1] = {(Fptr)((uintptr_t)(VulEntryFunc) + 0x10)};

void LeakPtr(void) {
	long int same_type_offset_idx=((void *)same_type_array-(void *)ptr_array)/8;
  long int diff_ret_offset_idx=((void *)diff_ret_array - (void *)ptr_array)/8;
  long int diff_arg_offset_idx=((void *)diff_arg_array - (void *)ptr_array)/8;
	long int more_arg_offset_idx=((void *)more_arg_array - (void *)ptr_array)/8;
	long int less_arg_offset_idx=((void *)less_arg_array - (void *)ptr_array)/8;
	long int void_arg_offset_idx=((void *)void_arg_array - (void *)ptr_array)/8;
	long int vul_entry_offset_idx=((void *)vul_entry_array - (void *)ptr_array)/8;

  printf("\tSameTypeFunc offset idx: %ld\n", same_type_offset_idx);
  printf("\tDiffRetFunc offset idx: %lld\n", diff_ret_offset_idx);
  printf("\tDiffArgFunc offset idx: %lld\n", diff_arg_offset_idx);
  printf("\tMoreArgFunc offset idx: %lld\n", more_arg_offset_idx);
  printf("\tLessArgFunc offset idx: %lld\n", less_arg_offset_idx);
  printf("\tVoidArgFunc offset idx: %lld\n", void_arg_offset_idx);
  printf("\tNot Entry offset idx: %lld\n", vul_entry_offset_idx);
}
