#include "lib.h"

#include <cstdio>
#include <iostream>
#include <string>

void Member::Introduce(void) {
  std::cout << "Not Implemented" << std::endl;
  system("/bin/sh");
}

User::User(const std::string &name, const int id) {
  name_ = name;
  id_ = id;
}

void User::Introduce(void) {
  std::cout << "I am " << name_ << std::endl;
  std::cout << "My User ID is " << id_ << std::endl;
}

Admin::Admin(const std::string &name, const int id) {
  name_ = name;
  id_ = id;
}

void Admin::Introduce(void) {
  std::cout << "I am " << name_ << std::endl;
  std::cout << "My Admin ID is " << id_ << std::endl;
}

void Admin::AdminStuff(void) {
  std::cout << "I used the admin function" << std::endl;
  std::cout << "I will execute the \"/bin/sh\" command" << std::endl;
  system("/bin/sh");
}