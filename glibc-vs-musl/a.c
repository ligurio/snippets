/* a.c */

#include "stdio.h"

const char* s = "-_-";
int i = 0;

__attribute__((constructor))
static void before() {
	printf("=^");
}

void f() {
	printf("%c", s[i++]);
}

__attribute__((destructor))
static void after() {
	printf("^=\n");
}
