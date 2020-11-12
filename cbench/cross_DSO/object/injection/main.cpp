#include "lib.h"
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>

void *vul_fun = (void *)getshell;
void *vul_gadget = (void *)((uintptr_t)(getshell) + 0x8);

void Execute(Admin *admin, User *user_a, User *user_b) {
  std::cout << "Admin registration:" << std::endl;
  admin->SetName();
  admin->AdminStuff();

  std::cout << "UserA registration:" << std::endl;
  user_a->SetName();
  user_a->AdminStuff();

  std::cout << "UserB registration:" << std::endl;
  user_b->SetName();
  user_b->AdminStuff();

  std::cout << "Rename admin:" << std::endl;
  admin->SetName();
  std::cout << "Check UserA again:" << std::endl;
  user_a->AdminStuff();
}

int main(int argc, const char *argv[]) {
  Admin *admin = new Admin();
  User *user_a = new User();
  User *user_b = new User();
  Member *vul = new Member;

  if (argc == 1) {
    printf("Do not need the argc");
    printf("It is the cross-DSO callback injection test\n");
    printf("the vul function  is :%p\n", &vul_fun);
    printf("the vul gadget is :%p\n", &vul_gadget);
    printf("if hacked successfully,it will getshell \n");
  }

  Execute(admin, user_a, user_b);
  return 0;
}
