#include "lib.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>

void getshell(void) {
  __asm__ volatile("nop\n"
                   "nop\n"
                   "nop\n"
                   "nop\n"
                   "nop\n"
                   "nop\n"
                   "nop\n"
                   "nop\n");
  std::cout << "you get shell!!" << std::endl;
  system("/bin/sh");
}

void *vul_fun = (void *)getshell;
void *vul_gadget = (void *)((uintptr_t)(getshell) + 0x8);

void Member::AdminStuff(void) { std::cout << "Not implemented" << std::endl; }

void Member::SetName(void) {
  std::cout << "plz input your name" << std::endl;
	read(0,name,0x20);
}

User::User(void) { permissions = "user"; }

void User::AdminStuff(void) {
  std::cout << "Hi,I am " << name << std::endl;
  std::cout << "Account  is: " << permissions << std::endl;
  std::cout << "Admin Work not permitted for a user account!" << std::endl;
}

Admin::Admin(void) { permissions = "admin"; }

void Admin::AdminStuff(void) {
  std::cout << "Hi,I am " << name << std::endl;
  std::cout << "Account  is: " << permissions << std::endl;
  std::cout << "Notice: Admin Work only permitted for a admin account! "
            << std::endl;
  std::cout << name << " would do  the Admin work " << std::endl;
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
