#include <stdio.h>
#include <stdlib.h>

void Ret(void) {
	char name[4];
	printf("plz input your name: \n");
	// vul
	read(0, name, 0x30);
}

void Test(void) { printf("In %s \n", __FUNCTION__); }

void Foo(void) {
	Ret();
	printf("In %s \n", __FUNCTION__); // normal callsite
	printf("Bye from foo\n");         // same function,different callsite
	exit(0);
}

void Bar(void) {
	Test();
	printf("In %s \n", __FUNCTION__); // same stack
	printf("Bye from bar\n");         // different function,different callsite
	exit(0);
}

void Entry(void) // function entry
{
	printf("In %s \n", __FUNCTION__);
	exit(0);
}

void Vul(void) {
	printf("In %s \n", __FUNCTION__); // no callsite
	__asm__ volatile("nop\n"
			"nop\n"
			"nop\n"
			"nop\n"
			"nop\n"
			"nop\n"
			"nop\n"
			"nop\n");
	printf("you get shell!!\n");
	system("/bin/sh");
	exit(0);
}

int main(int argc, const char *argv[]) {
	printf("In %s \n", __FUNCTION__);

	if (argc != 1) {
		printf("it is a easy ROP test\n");
		printf("Ret is a vulnerable function\n");
		printf("Foo is %p\n",(void *)Foo);
		printf("Bar is %p\n",(void *)Bar);
		printf("Entry is %p\n",(void *)Entry);
		printf("Vul is %p\n",(void *)Vul);
		return 1;
	}

	Foo();
	Bar();

	return 0;
}
