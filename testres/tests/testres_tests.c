#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

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
		cmocka_unit_test(test_junit),
		cmocka_unit_test(test_testanything),
		cmocka_unit_test(test_subunit),
	};

	/* Run series of tests */
	return cmocka_run_group_tests(tests, NULL, NULL);
}

/*
 * ----------------------
 *  Definitions of tests
 * ----------------------
 */

/* Basic JUnit format support */
static void
test_junit(void **state)
{
	assert_int_equal(99, 99);
	assert_int_equal(0, 0);
	assert_int_equal(0, 0);
}


/* Basic TAP format support */
static void
test_testanything(void **state)
{
	assert_int_equal(99, 99);
	assert_int_equal(0, 0);
	assert_int_equal(0, 0);
}


/* Basic SubUnit format support */
static void
test_subunit(void **state)
{
	assert_int_equal(99, 99);
	assert_int_equal(0, 0);
	assert_int_equal(0, 0);
}
