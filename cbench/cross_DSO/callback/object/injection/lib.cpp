#include "lib.h"

#include <cstdio>
#include <iostream>
#include <string>

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
