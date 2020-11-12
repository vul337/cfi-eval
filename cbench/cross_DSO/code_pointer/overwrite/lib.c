#include "lib.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef void (*Fptr)(int, int);

__attribute__((visibility("default"))) void SameTypeFunc(int a, int b) {
  printf("In %s \n", __FUNCTION__);
}

__attribute__((visibility("default"))) int DiffRetFunc(int a, int b) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}

__attribute__((visibility("default"))) void DiffArgFunc(int a, float b) {
  printf("In %s \n", __FUNCTION__);
}

__attribute__((visibility("default"))) void MoreArgFunc(int a, int b, int c) {
  printf("In %s \n", __FUNCTION__);
}

__attribute__((visibility("default"))) void LessArgFunc(int a) {
  printf("In %s \n", __FUNCTION__);
}

__attribute__((visibility("default"))) void VoidArgFunc(void) {
  printf("In %s \n", __FUNCTION__);
}

__attribute__((visibility("default"))) void VulEntryFunc(int a, int b) {
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

__attribute__((visibility("default"))) void Foo(int a, int b) {
  printf("In %s\n", __FUNCTION__);
}

__attribute__((visibility("default"))) void Bar(int a, int b) {
  printf("In %s\n", __FUNCTION__);
}

__attribute__((visibility("default"))) void LeakPtr(void) {
  printf("\tSameTypeFunc: %p\n", (void *)SameTypeFunc);
  printf("\tDiffRetFunc: %p\n", (void *)DiffRetFunc);
  printf("\tDiffArgFunc: %p\n", (void *)DiffArgFunc);
  printf("\tMoreArgFunc: %p\n", (void *)MoreArgFunc);
  printf("\tLessArgFunc: %p\n", (void *)LessArgFunc);
  printf("\tVoidArgFunc: %p\n", (void *)VoidArgFunc);
  printf("\tNot Entry: %p\n", (void *)(VulEntryFunc + 0x10));
}
