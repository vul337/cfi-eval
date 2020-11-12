#include <stdio.h>
#include <stdlib.h>

typedef int (*Fptr)(int, int);

int SameTypeFunc(int a, int b) {
  printf("In %s \n", __FUNCTION__);
  exit(0);
}

void DiffRetFunc(int a, int b) {
  printf("In %s \n", __FUNCTION__);
  exit(0);
}

int DiffArgFunc(int a, float b) {
  printf("In %s \n", __FUNCTION__);
  exit(0);
}

int MoreArgFunc(int a, int b, int c) {
  printf("In %s \n", __FUNCTION__);
  exit(0);
}

int LessArgFunc(int a) {
  printf("In %s \n", __FUNCTION__);
  exit(0);
}

int VoidArgFunc(void) {
  printf("In %s \n", __FUNCTION__);
  exit(0);
}

int VulEntryFunc(int a, int b) {
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

int Foo(int a, int b) {
  printf("In %s\n", __FUNCTION__);
  exit(0);
}

int main(int argc, const char *argv[]) {
    printf("inline indirect jump test\n");
    printf("\tSameTypeFunc: %p\n", (void *)SameTypeFunc);
    printf("\tDiffRetFunc: %p\n", (void *)DiffRetFunc);
    printf("\tDiffArgFunc: %p\n", (void *)DiffArgFunc);
    printf("\tMoreArgFunc: %p\n", (void *)MoreArgFunc);
    printf("\tLessArgFunc: %p\n", (void *)LessArgFunc);
    printf("\tVoidArgFunc: %p\n", (void *)VoidArgFunc);
    printf("\tnot_entry: %p\n", (void *)(VulEntryFunc + 0x10));

  printf("In %s\n", __FUNCTION__);

  Fptr ptr = Foo;
  char name[8];
	printf("ptr is %p\n",&ptr);
	printf("name is %p\n",&name);
  // buffer overflow
  printf("plz input your name:\n");
  read(0, name, 0x20);
  asm volatile("jmp *%0" : : "m"(ptr));

  return 0;
}
