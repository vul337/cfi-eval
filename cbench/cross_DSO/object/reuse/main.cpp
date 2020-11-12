#include "lib.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <unistd.h>

int main(int argc, char *argv[]) {
  User *userA = new User("Jack", 20181009);
  User *userB = new User("Jane", 20181007);
  Admin *adminA = new Admin("Harry", 20140921);
  Member *vul = new Member;

  if (argc != 1) {
    void **base_vtable = *(void ***)vul;
    void **same_vtable = *(void ***)userB;
    void **diff_vtable = *(void ***)adminA;
    printf("Do not need the argc");
    printf("It is the UAF_ptr_reuse test\n");
    printf("the base class vtable address is %p\n", base_vtable);
    printf("the same class vtable address is %p\n", same_vtable);
    printf("the different target vtable address is %p\n", diff_vtable + 1);
    printf("if hacked successfully,it will get the shell \n");
    return 1;
  }

  std::cout << "There are two members" << std::endl;
  userA->Introduce();
  adminA->Introduce();

  size_t len;
  char *data;
  unsigned int op;
  while (1) {
    std::cout << "1. introduce\n2. malloc\n3. delete\n4. exit\n";
    scanf("%d", &op);

    switch (op) {
    case 1:
      userA->Introduce();
      break;
    case 2:
      std::cout << "len:" << std::endl;
      scanf("%ld", &len);
      data = new char[len];
      std::cout << "data:" << std::endl;
      read(0, data, len);
      std::cout << "your data is allocated" << std::endl;
      break;
    case 3:
      std::cout << "We will delete the member" << std::endl;
      delete userA;
      break;
    default:
      break;
    }
    if (op == 4)
      break;
  }

  return 0;
}
