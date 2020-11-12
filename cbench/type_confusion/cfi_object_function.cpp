#include <cassert>
#include <cstring>
#include <iostream>

struct User {
  virtual int Foo(void);
  virtual void Bar(void);
};

int User::Foo(void) {
  std::cout << "I am user" << std::endl;
  return 1;
}

void User::Bar(void) { std::cout << "Bye" << std::endl; }

struct Admin {
  virtual void Foo(void);
  virtual int Bar(void);
};

void Admin::Foo(void) { std::cout << "I am admin" << std::endl; }

int Admin::Bar(void) {
  std::cout << "Bye" << std::endl;
  return 2;
}

typedef int (Admin::*AdminInt)(void);
template <typename To, typename From> To BitCast(From f) {
  assert(sizeof(To) == sizeof(From));
  To t;
  memcpy(&t, &f, sizeof(f));
  return t;
}

int main(int argc, const char *argv[]) {
  User user;
  Admin admin;

  // runtime error: control flow integrity check failed
  // during virtual pointer to member function call note: vtable is of type
  // 'Admin'
  int k = (admin.*BitCast<AdminInt>(&User::Foo))();
  std::cout << k << std::endl;

  return 0;
}
