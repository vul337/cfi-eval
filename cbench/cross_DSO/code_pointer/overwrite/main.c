#include "lib.h"

#include <stdio.h>

typedef void (*Fptr)(int, int);

int main(int argc, const char *argv[]) {
  printf("In %s\n", __FUNCTION__);

  Fptr ptr = Foo;
  if (argc > 1)
    ptr = Bar;
  printf("ptr is: %p\n", ptr);
  printf("ptr address is: %p\n", &ptr);

  LeakPtr();
  // Assuming that the attacker has the ability to write to any address
  void **anyptr;
  printf("plz input the value of anyptr: \n");
  scanf("%p", &anyptr);
  printf("plz change the value of *anyptr: \n");
  scanf("%p", anyptr);
  ptr(0, 0);

  return 0;
}
