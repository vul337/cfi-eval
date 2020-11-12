#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
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
  std::string name_;

public:
  virtual void Introduce(void);
};

void Member::Introduce(void) { std::cout << "Not Implemented" << std::endl; }

class User : public Member {
public:
  User(const std::string &name, const int id);
  virtual void Introduce(void);
};

User::User(const std::string &name, const int id) {
  name_ = name;
  id_ = id;
}

void User::Introduce(void) {
  std::cout << "I am " << name_ << std::endl;
  std::cout << "My User ID is " << id_ << std::endl;
}

class Admin : public Member {
public:
  Admin(const std::string &name, const int id);
  virtual void Introduce(void);
};

Admin::Admin(const std::string &name, const int id) {
  name_ = name;
  id_ = id;
}

void Admin::Introduce(void) {
  std::cout << "I am " << name_ << std::endl;
  std::cout << "My Admin ID is " << id_ << std::endl;
}

int main(int argc, char *argv[]) {
  if (argc != 1) {
    printf("Do not need the argc");
    printf("the vul is use after free\n");
    printf("the vul function is address :%p\n", vul_fun);
    printf("the vul gadget is address:%p\n", vul_gadget);
    printf("the vul function  is :%p\n", &vul_fun);
    printf("the vul gadget is :%p\n", &vul_gadget);
    printf("if hacked successfully,it will jump to %p\n", (void *)getshell);
    return 1;
  }

  User *user = new User("Jack", 20181009);
  Admin *admin = new Admin("Harry", 20140921);

  std::cout << "There are two members" << std::endl;
  user->Introduce();
  admin->Introduce();

  size_t size;
  char *data;
  unsigned int op;
  while (1) {
    std::cout << "1. introduce\n2. malloc\n3. delete\n4. exit\n";
    scanf("%d", &op);

    switch (op) {
    case 1:
      user->Introduce();
      admin->Introduce();
      break;
    case 2:
      std::cout << "you can allocate some data and the size is:" << std::endl;
      scanf("%ld", &size);
      data = new char[size];
      std::cout << "your data is:" << std::endl;
      read(0, data, size);
      std::cout << "your data is allocated" << std::endl;
      break;
    case 3:
      std::cout << "We will delete the member" << std::endl;
      delete user;
      delete admin;
      break;
    default:
      break;
    }
    if (op == 4)
      break;
  }

  return 0;
}
