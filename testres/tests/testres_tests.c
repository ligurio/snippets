#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "parse_junit.h"
#include "parse_testanything.h"

/*
 * -----------------------
 *  Declarations of tests
 * -----------------------
 */

static void test_junit(void **state);
static void test_testanything(void **state);
static void test_subunit(void **state);

/* Entrypoint */
int
main(void)
{
	/* Array of test functions */
	const struct CMUnitTest tests[] =
	{
		cmocka_unit_test(test_testanything),
		cmocka_unit_test(test_subunit),
		cmocka_unit_test(test_junit),
	};

	/* Run series of tests */
	return cmocka_run_group_tests(tests, NULL, NULL);
}

/*
 * ----------------------
 *  Definitions of tests
 * ----------------------
 */

/* Basic TAP format support */
static void
test_testanything(void **state)
{
    skip();
/*
    char *filename = "./tests/testanything/example.tap";
    struct ast_test *tests;
    FILE *f;
    f = fopen(filename, "r");
    tests = parse_testanything(f);
    fclose(f);
    print(stdout, tests);
    assert_int_equal(99, 99);
*/
}


/* Basic SubUnit format support */
static void
test_subunit(void **state)
{
    skip();
}


/* Basic JUnit format support */
static void
test_junit(void **state)
{
    skip();
}
