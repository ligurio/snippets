/*  gcc os-test-mem.c -o os-test-mem -I/usr/local/include -L/usr/local/lib -lcmocka */

#ifdef __HAIKU__
#define _BSD_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

static void malloc_0(void **state) {
    (void) state;
	errno = 0;
	void* ptr = malloc(0);
	if ( ptr )
		puts("non-NULL");
	else if ( errno != 0 )
		err(1, "malloc");
	else
		puts("NULL");
	return 0;
}

/* Tests whether realloc(NULL, 0) returns non-zero. */
int realloc_null_0(void)
{
	errno = 0;
	void* newptr = realloc(NULL, 0);
	if ( newptr )
		puts("non-NULL");
	else if ( errno )
		err(1, "realloc");
	else
		puts("NULL");
	return 0;
}

/* Tests whether realloc(ptr, 0) returns non-zero. */
int realloc_0(void)
{
	void* ptr = malloc(1);
	if ( !ptr )
		err(1, "malloc");
	errno = 0;
	void* newptr = realloc(ptr, 0);
	if ( newptr )
		puts("non-NULL");
	else if ( 0 < errno )
		err(1, "realloc");
	else
	{
		/* realloc returns NULL without setting errno. That means the allocation
		   been freed and we didn't get a replacement allocation. This behavior
		   is undesirable in my opinion because it causes much more compexity
		   and makes realloc much harder to use without a check for whether size
		   is zero. Unfortunately C11 with DR400
		   <http://open-std.org/jtc1/sc22/wg14/www/docs/summary.htm#dr_400>
		   now allows this behavior and marks using realloc with size == 0 as
		   obsolescent. POSIX issue 7 (2018) also allows this behavior, even
		   though its rationale doesn't like it. It does require errno to be set
		   to an implementation specific value in this case, which no
		   implementation does, so I guess that means keeping errno unchanged.
		   Therefore this case is allowed by the standards. It does make the
		   interface much harder to use for arbitrary lengths and can cause
		   double free and use after free bugs if software doesn't know to take
		   care. */
		puts("NULL");
	}
	return 0;
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(malloc_0),
        cmocka_unit_test(realloc_0),
        cmocka_unit_test(realloc_null_0),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
