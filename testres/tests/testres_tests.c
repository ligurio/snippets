#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>
#include <assert.h>
#include <arpa/inet.h>

#ifndef PARSE_COMMON_H
#define PARSE_COMMON_H
#include "parse_common.h"
#endif /* PARSE_COMMON_H */

#include "parse_junit.h"
#include "parse_testanything.h"
#include "parse_subunit_v2.h"

#define SAMPLE_FILE_JUNIT "samples/junit/junit-sample-1.xml"
#define SAMPLE_FILE_SUBUNIT_V2 "samples/subunit/subunit-sample-02.subunit"
#define SAMPLE_FILE_TESTANYTHING "samples/testanything/tap-sample-01.tap"

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

static void test_list(void **state);

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
		cmocka_unit_test(test_list),
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
    /* parse via parse() and parse_subunit_v2() and compare structs */

    FILE *file;
    char *name = SAMPLE_FILE_TESTANYTHING;
    report_t *report1, *report2;

    file = fopen(name, "r");
    if (file == NULL)
    {
        fail();
    }
    report1 = parse_testanything(file);
    report2 = process_file(name);
    fclose(file);

    assert(report1->format == report2->format);

    /* FIXME: free report1 and report2 */
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
    test_t * test;
    FILE* stream = open_memstream(&buf, &buf_size);
    fwrite(&sample_header, 1, sizeof(sample_header), stream);
    fwrite(&sample_length, 1, sizeof(sample_length), stream);
    fwrite(&sample_testid, 1, sizeof(sample_testid), stream);
    fwrite(&sample_crc32, 1, sizeof(sample_crc32), stream);
    test = read_packet(stream);

    assert_string_equal(test->name, "");
    /* FIXME: free test */
    fclose(stream);
    free(buf);
}


static void
test_parse_subunit(void **state)
{
    char *name = SAMPLE_FILE_SUBUNIT_V2;
    FILE *file;

    file = fopen(name, "r");
    if (file == NULL)
    {
        fail();
    }
    report_t *report;
    report = parse_subunit_v2(file);
    assert(report->format == FORMAT_SUBUNIT_V2);
    /* FIXME: free report */
    fclose(file);
}

static void
test_parse_subunit_common(void **state)
{
    /* parse via parse() and parse_subunit_v2() and compare structs */

    FILE *file;
    char *name = SAMPLE_FILE_SUBUNIT_V2;
    report_t *report1, *report2;

    file = fopen(name, "r");
    if (file == NULL)
    {
        fail();
    }
    report1 = parse_subunit_v2(file);
    report2 = process_file(name);
    fclose(file);

    assert(report1->format == report2->format);

    /* FIXME: free report1 and report2 */
}

/* Basic JUnit format support */
static void
test_parse_junit(void **state)
{
    FILE *file;
    char *name = SAMPLE_FILE_JUNIT;
    report_t *report;

    file = fopen(name, "r");
    if (file == NULL)
    {
        fail();
    }
    report = parse_junit(file);
    assert(report->format == FORMAT_JUNIT);
    /* FIXME: free report */
    fclose(file);
}

static void
test_parse_junit_common(void **state)
{
    /* parse via parse() and parse_junit() and compare structs */

    FILE *file;
    char *name = SAMPLE_FILE_JUNIT;
    report_t *report1, *report2;

    file = fopen(name, "r");
    if (file == NULL)
    {
        fail();
    }
    report1 = parse_junit(file);
    report2 = process_file(name);
    fclose(file);

    assert(report1->format == report2->format);

    /* FIXME: free report1 and report2 */
}

static void
test_list(void **state) {

    /* see https://github.com/clibs/list/blob/master/test.c */

    /*
    test_t * test;
    test = malloc(sizeof(test_t));
    if (test == NULL) {
        fail();
    }
    memset(test, 0, sizeof(test_t));
    test->name = "test1";
    test->time = "12:45:56";
    test->status = STATUS_OK;
    test->next = NULL;

    suite_t * suite;
    suite = malloc(sizeof(suite_t));
    if (suite == NULL) {
        fail();
    }
    memset(suite, 0, sizeof(suite_t));
    suite->name = "suite1";
    suite->test = test;
    suite->n_failures = 10;
    suite->n_errors = 11;
    suite->next = NULL;

    report_t * report;
    report = malloc(sizeof(report_t));
    if (report == NULL) {
        fail();
    }
    memset(report, 0, sizeof(report_t));
    report->format = FORMAT_SUBUNIT_V1;
    report->suite = suite;
    report->next = NULL;

    print_reports(report);
    delete_reports(report);
    */
}
