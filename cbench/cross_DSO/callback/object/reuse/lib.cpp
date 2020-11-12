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

	std::cout << "UserA Rename:" << std::endl;
	user_a->SetName();

	std::cout << "Check UserB again:" << std::endl;
	user_b->AdminStuff();
}
