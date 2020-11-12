#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <unistd.h>

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

class Member {
protected:
  int id_;
  std::string permissions_;
  char name_[4];

public:
  virtual void AdminStuff(void);
  virtual void SetName(void);
};

void Member::AdminStuff(void) { std::cout << "Not Implemented" << std::endl; }

void Member::SetName(void) {
  std::cout << "plz input your name" << std::endl;
  read(0, name_, 0x20);
}

class User : public Member {
public:
  User(void);
  virtual void AdminStuff(void);
};

User::User(void) { permissions_ = "user"; }

void User::AdminStuff(void) {
  std::cout << "Hi,I am " << name_ << std::endl;
  std::cout << "Account  is: " << permissions_ << std::endl;
  std::cout << "Admin Work not permitted for a user account!" << std::endl;
}

class Admin : public Member {
public:
  Admin(void);
  virtual void AdminStuff(void);
};

Admin::Admin(void) { permissions_ = "Admin"; }

void Admin::AdminStuff(void) {
  std::cout << "Hi,I am " << name_ << std::endl;
  std::cout << "Account  is: " << permissions_ << std::endl;
  std::cout << "Notice: Admin Work only permitted for a admin account! "
            << std::endl;
  std::cout << name_ << " would do  the Admin work " << std::endl;
}

int main(int argc, const char *argv[]) {
  Admin *admin = new Admin();
  User *user_a = new User();
  User *user_b = new User();
  Member *vul = new Member;

  if (argc != 1) {
    printf("Do not need the argc");
    printf("the vul is read\n");
    printf("the vul function is address :%p\n", vul_fun);
    printf("the vul gadget is address:%p\n", vul_gadget);
    printf("the vul function  is :%p\n", &vul_fun);
    printf("the vul gadget is :%p\n", &vul_gadget);
    printf("if hacked successfully,it will jump to %p\n", (void *)getshell);
  }

  std::cout << "Admin registration:" << std::endl;
  admin->SetName();
  admin->AdminStuff();

  std::cout << "UserA registration:" << std::endl;
  user_a->SetName();
  user_a->AdminStuff();

  std::cout << "UserB registration:" << std::endl;
  user_b->SetName();
  user_b->AdminStuff();

  std::cout << "UserA Rename:" << std::endl;
  user_a->SetName();

  std::cout << "Check UserB again:" << std::endl;
  user_b->AdminStuff();

  return 0;
}
