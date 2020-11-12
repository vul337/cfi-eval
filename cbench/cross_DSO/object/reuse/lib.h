#pragma once

#include <string>

class Member {
protected:
  int id_;
  std::string name_;

public:
  virtual void Introduce(void);
};

class User : public Member {
public:
  User(const std::string &name, const int id);
  virtual void Introduce(void);
};

class Admin : public Member {
public:
  Admin(const std::string &name, const int id);
  virtual void Introduce(void);
  virtual void AdminStuff(void);
};
