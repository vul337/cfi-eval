#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
typedef int (*SameTypeFunc_)(int, int);
typedef void (*DiffRetFunc_)(int, int);
typedef int (*DiffArgFunc_)(int, float);
typedef int (*MoreArgFunc_)(int, int, int);
typedef int (*LessArgFunc_)(void);
typedef int (*VoidArgFunc_)(int);

int SameTypeFunc1(int a, int b) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}

int SameTypeFunc2(int a, int b) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}

void DiffRetFunc1(int a, int b) { printf("In %s \n", __FUNCTION__); }
void DiffRetFunc2(int a, int b) { printf("In %s \n", __FUNCTION__); }

int DiffArgFunc1(int a, float b) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}
int DiffArgFunc2(int a, float b) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}

int MoreArgFunc1(int a, int b, int c) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}
int MoreArgFunc2(int a, int b, int c) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}

int LessArgFunc1(int a) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}
int LessArgFunc2(int a) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}

int VoidArgFunc1(void) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}
int VoidArgFunc2(void) {
  printf("In %s \n", __FUNCTION__);
  return 0;
}

int Foo(int a, int b) {
  printf("In %s\n", __FUNCTION__);
  return 1;
}

int Bar(int a, int b) {
  printf("In %s\n", __FUNCTION__);
  return 0;
}

struct FuncPtr {
  SameTypeFunc_ correct_func[1];
  SameTypeFunc_ same_type_func[1];
  DiffArgFunc_ diff_arg_func[1];
  DiffRetFunc_ diff_ret_func[1];
  MoreArgFunc_ more_arg_func[1];
  LessArgFunc_ less_arg_func[1];
  VoidArgFunc_ void_arg_func[1];
};

// the struct aligns the function pointer arrays
// so indexing past the end will reliably call working function pointers
static struct FuncPtr fptr1 = {
    .correct_func = {Foo},
    .same_type_func = {SameTypeFunc1},
    .diff_arg_func = {DiffArgFunc1},
    .diff_ret_func = {DiffRetFunc1},
    .more_arg_func = {MoreArgFunc1},
    .less_arg_func = {LessArgFunc1},
    .void_arg_func = {VoidArgFunc1},
};

static struct FuncPtr fptr2 = {
    .correct_func = {Bar},
    .same_type_func = {SameTypeFunc2},
    .diff_arg_func = {DiffArgFunc2},
    .diff_ret_func = {DiffRetFunc2},
    .more_arg_func = {MoreArgFunc2},
    .less_arg_func = {LessArgFunc2},
    .void_arg_func = {VoidArgFunc2},
};
int idx;

int Excute(void) {
  printf("Calling a function:\n");
  scanf("%d", &idx);
  sleep(3);
  return fptr1.correct_func[idx](idx, idx);
}

void *UseIdx(void *args) {
  if (Excute())
    printf("success exit\n");
}

void *IncreaseIdx(void *args) {
	sleep(1);
  printf("plz input index:\n");
  scanf("%d", &idx);
}

int main(int argc, const char *argv[]) {

  printf("0: the correct function\n");
  printf("1-6: out of bound access inside the same object\n");
  printf("\tthe correct function: %p\n", (void *)fptr1.correct_func);
  printf("let test the out of bound access inside the other object\n");
  printf("\tthe same-type function infptr2: %p\n", (void *)fptr2.correct_func);
  printf("The bar-based offset is sequentially increased by 1-6\n");

  pthread_t a, b;
  pthread_create(&a, NULL, UseIdx, NULL);
  pthread_create(&b, NULL, IncreaseIdx, NULL);
  pthread_join(a, NULL);
  pthread_join(b, NULL);

  // Excute(argv);
  return 0;
}
