#include "lib.h"
#include <cstdio>
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
