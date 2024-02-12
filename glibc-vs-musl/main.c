/* main.c */

#include "dlfcn.h"

int main()
{
	for (int i = 0; i < 3; i++) {
		void* a = dlopen("./liba.so", RTLD_LAZY);
		void(*f)() = dlsym(a, "f");
		f();
		dlclose(a);
	}
}
