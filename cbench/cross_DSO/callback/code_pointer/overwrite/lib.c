#include "lib.h"
#include <stdio.h>

typedef int (*Fptr)(int, int);

__attribute__((visibility("default"))) void Callback(Fptr ptr) {
  int k = rand() % 100;
  Fptr fptr;
  char name[4];

  fptr = ptr;

  printf("ptr is: %p\n", fptr);
  printf("ptr address is: %p\n", &fptr);
  // Assuming that the attacker has the ability to write to any address
  void **anyptr;
  printf("plz input the value of anyptr: \n");
  scanf("%p", &anyptr);
  printf("plz change the value of *anyptr: \n");
  scanf("%p", anyptr);

  fptr(0, 0);
}
