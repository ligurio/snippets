#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>
#include <arpa/inet.h>

#ifndef PARSE_COMMON_H
#define PARSE_COMMON_H
#include "parse_common.h"
#endif /* PARSE_COMMON_H */

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

static void test_parse_testanything_common(void **state);
static void test_parse_testanything(void **state);

static void test_parse_subunit_packet(void **state);
static void test_parse_subunit_common(void **state);
static void test_parse_subunit(void **state);

static void test_parse_junit_common(void **state);
static void test_parse_junit(void **state);

/* Entrypoint */
int
main(void)
{
	/* Array of test functions */
	const struct CMUnitTest tests[] =
	{
		cmocka_unit_test(test_parse_testanything_common),
		cmocka_unit_test(test_parse_testanything),
		cmocka_unit_test(test_parse_subunit_packet),
		cmocka_unit_test(test_parse_subunit_common),
		cmocka_unit_test(test_parse_subunit),
		cmocka_unit_test(test_parse_junit_common),
		cmocka_unit_test(test_parse_junit),
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
test_parse_testanything(void **state)
{
    char *name = SAMPLE_FILE_TESTANYTHING;
    report_t *report;
    FILE *file;
    file = fopen(name, "r");
    if (file == NULL) {
       fail();
    }
    parse_testanything(file);
    fclose(file);
}

static void
test_parse_testanything_common(void **state)
{
    char *name = SAMPLE_FILE_TESTANYTHING;
    skip();
    /* parse via parse() and parse_testanything() and compare structs */
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

    report_t *report;
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
test_parse_subunit(void **state)
{
    char *name = SAMPLE_FILE_SUBUNIT_V2;
    report_t *report;
    FILE *file;

    file = fopen(name, "r");
    if (file == NULL)
    {
        fail();
    }
    report = parse_subunit_v2(file);
    fclose(file);
}

static void
test_parse_subunit_common(void **state)
{
    /* parse via parse() and parse_subunit_v2() and compare structs */
    skip();
}

/* Basic JUnit format support */
static void
test_parse_junit(void **state)
{
    FILE *file;
    char *name = SAMPLE_FILE_JUNIT;
    skip();
}

static void
test_parse_junit_common(void **state)
{
    /* parse via parse() and parse_junit() and compare structs */
    skip();
}
