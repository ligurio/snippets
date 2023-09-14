/*
 * gcc test.c -o test -I/usr/local/include -pthread -L/usr/local/lib -lcheck
 * gcc cmocka.c -o cmocka -L/usr/local/lib -lcmocka -I/usr/local/include
 * CMOCKA_MESSAGE_OUTPUT=XML CMOCKA_XML_FILE=cm_%g.xml ./cmocka
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <unistd.h>

#define COMMAND "/usr/bin/true"

static void execute_test(void **state) {
    (void) state;
	int rc = 0;
	rc = execl(COMMAND, NULL);
	if (rc == -1) {
		fail();
    }
}

static int gr_setup(void **state) {
     return 0;
}

static int gr_teardown(void **state) {
     return 0;
}

static int ve_teardown(void **state) {
     return 0;
}

static int ve_setup(void **state) {
     return 0;
}

int main(void) {
    const struct CMUnitTest tests1[] = {
        cmocka_unit_test(execute_test),
        cmocka_unit_test_setup_teardown(execute_test, ve_setup, ve_teardown),
        cmocka_unit_test(execute_test),
        cmocka_unit_test(execute_test),
        cmocka_unit_test(execute_test),
    };

    const struct CMUnitTest tests2[] = {
        cmocka_unit_test(execute_test),
        cmocka_unit_test(execute_test),
        cmocka_unit_test(execute_test),
        cmocka_unit_test(execute_test),
    };

    cmocka_run_group_tests(tests1, NULL, NULL);
    cmocka_run_group_tests(tests2, NULL, NULL);
	cmocka_run_group_tests_name("tests XXX", tests2, gr_setup, gr_teardown);
}
