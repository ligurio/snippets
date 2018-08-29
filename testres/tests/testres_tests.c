#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>

#include <arpa/inet.h>

#include "parse_junit.h"
#include "parse_testanything.h"
#include "parse_subunit_v2.h"

#define SAMPLE_FILE_JUNIT "junit/junit-sample-1.xml"
#define SAMPLE_FILE_SUBUNIT_V2 "subunit/subunit-sample-02.subunit"
#define SAMPLE_FILE_TESTANYTHING "testanything/tap-sample-01.tap"

/*
 * -----------------------
 *  Declarations of tests
 * -----------------------
 */

static void test_parse_testanything_sample(void **state);
static void test_parse_subunit_packet(void **state);
static void test_parse_subunit_sample(void **state);
static void test_parse_junit_sample(void **state);

/* Entrypoint */
int
main(void)
{
	/* Array of test functions */
	const struct CMUnitTest tests[] =
	{
		cmocka_unit_test(test_parse_testanything_sample),
		cmocka_unit_test(test_parse_subunit_packet),
		cmocka_unit_test(test_parse_subunit_sample),
		cmocka_unit_test(test_parse_junit_sample),
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
test_parse_testanything_sample(void **state)
{
    char *name = SAMPLE_FILE_TESTANYTHING;
    struct ast_test *tests;
    FILE *file;
    file = fopen(name, "r");
    if (file == NULL) {
       fail();
    }
    tests = parse_testanything(file);
    fclose(file);
    //print(stdout, tests);
}


/* Basic SubUnit format support */
static void
test_parse_subunit_packet(void **state)
{
    // Packet sample, with test id, runnable set, status=enumeration.
    // Spaces below are to visually break up:
    // signature / flags / length / testid / crc32
    // b3 2901 0c 03666f6f 08555f1b
    // echo 03666f6f | xxd -p -r

    subunit_header sample_header = { .signature = 0xb3, .flags = ntohs(0x2901) };
    uint16_t sample_length = 0x0c;
    uint32_t sample_testid = 0x03666f6f;
    uint32_t sample_crc32 = 0x08555f1b;

    char* buf = NULL;
    size_t buf_size = 0;
    FILE* stream = open_memstream(&buf, &buf_size);
    fwrite(&sample_header, 1, sizeof(sample_header), stream);
    fwrite(&sample_length, 1, sizeof(sample_length), stream);
    fwrite(&sample_testid, 1, sizeof(sample_testid), stream);
    fwrite(&sample_crc32, 1, sizeof(sample_crc32), stream);
    read_packet(stream);
    fclose(stream);
    free(buf);
}


static void
test_parse_subunit_sample(void **state)
{
    FILE *file;
    char *name = SAMPLE_FILE_SUBUNIT_V2;
    file = fopen(name, "r");
    if (file == NULL)
    {
        fail();
    }
    read_stream(file);
    fclose(file);
}


/* Basic JUnit format support */
static void
test_parse_junit_sample(void **state)
{
    FILE *file;
    char *name = SAMPLE_FILE_JUNIT;
    skip();
}
