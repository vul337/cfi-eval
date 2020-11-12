#include <iostream>

class Member {
protected:
  int id_;
  std::string name_;
};

class User : public Member {
public:
  User(const std::string &name, int id);
  virtual void Introduce(void);
};

User::User(const std::string &name, int id) {
  name_ = name;
  id_ = id;
}

void User::Introduce(void) {
  std::cout << "I am " << name_ << std::endl;
  std::cout << "My User ID is " << id_ << std::endl;
}

class Admin : public Member {
public:
  Admin(const std::string &name, int id);
  virtual void admin(void);
};

Admin::Admin(const std::string &name, int id) {
  name_ = name;
  id_ = id;
}

void Admin::admin(void) {
  std::cout << "I am " << name_ << std::endl;
  std::cout << "My admin ID is " << id_ << std::endl;
  std::cout << "I used the admin function" << std::endl;
  std::cout << "I will execute the \"/bin/sh\" command" << std::endl;
  system("/bin/sh");
}

int main(int argc, const char *argv[]) {
  Admin *admin = new Admin("Harry", 405);
  User *user = new User("Jack", 201);

  user->Introduce();

  user = reinterpret_cast<User *>(admin);
  user->Introduce();

  return 0;
}
