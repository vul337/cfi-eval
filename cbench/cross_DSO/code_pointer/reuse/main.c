#include "lib.h"

#include <stdio.h>
#include <stdlib.h>
//extern Fptr *ptr_array;

int main(int argc, const char *argv[]) {
  printf("In %s \n", __FUNCTION__);

  LeakPtr();
  printf("Calling a function:\n");
	long int idx;
  printf("plz input the idx:\n");
	scanf("%ld",&idx);
  ptr_array[idx](idx, idx);
  return 0;
}
