#include "lib.h"

__attribute__((visibility("default")))void Ret(void) {
  char name[4];
  printf("plz input your name: \n");
  // vul
  read(0,name,0x30);
}

__attribute__((visibility("default")))void Test(void) { printf("In %s \n", __FUNCTION__); }
