#pragma once

typedef int (*Fptr)(int, int);

extern Fptr ptr_array[1];

void LeakPtr(void);
