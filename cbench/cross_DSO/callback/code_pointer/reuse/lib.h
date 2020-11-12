#pragma once

typedef int (*SameTypeFunc_)(int, int);
typedef void (*DiffRetFunc_)(int, int);
typedef int (*DiffArgFunc_)(int, float);
typedef int (*MoreArgFunc_)(int, int, int);
typedef int (*LessArgFunc_)(void);
typedef int (*VoidArgFunc_)(int);

struct FuncPtr {
  SameTypeFunc_ correct_func[1];
  SameTypeFunc_ same_type_func[1];
  DiffArgFunc_ diff_arg_func[1];
  DiffRetFunc_ diff_ret_func[1];
  MoreArgFunc_ more_arg_func[1];
  LessArgFunc_ less_arg_func[1];
  VoidArgFunc_ void_arg_func[1];
};

extern int Bar(int a, int b);
extern int Foo(int a, int b);

extern void Callback(struct FuncPtr fptr, int arg);
