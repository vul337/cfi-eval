#include <stdio.h>

typedef void (*IntArgFunc)(int x);
typedef void (*IntIntArgFunc)(int x, int y);

void Print(int x) { printf("the number is %d\n", x); }

void Add(int x, int y) { printf("%d + %d = %d\n", x, y, x + y); }

int main(void) {
  IntArgFunc confusion = (IntArgFunc)Add;
  confusion(233);
  IntIntArgFunc confusion2 = (IntIntArgFunc)Print;
  confusion2(233, 666);
}
