#pragma once

typedef int (*Fptr)(int, int);

extern int Bar(int a, int b);
extern int Foo(int a, int b);

extern void Callback(Fptr ptr);
