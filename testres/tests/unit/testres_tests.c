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
#include "parse_subunit_v1.h"
#include "parse_subunit_v2.h"

#define SAMPLE_FILE_JUNIT "../samples/junit.xml"
#define SAMPLE_FILE_SUBUNIT_V1 "../samples/subunit_v1.subunit"
#define SAMPLE_FILE_SUBUNIT_V2 "../samples/subunit_v2.subunit"
#define SAMPLE_FILE_TESTANYTHING "../samples/testanything.tap"

/*
 * -----------------------
 *  Declarations of tests
 * -----------------------
 */

static void test_parse_testanything_common(void **state);
static void test_parse_testanything(void **state);

static void test_subunit_version(void **state);

static void test_parse_subunit_v1(void **state);
static void test_parse_subunit_v1_line(void **state);

static void test_parse_subunit_v2_packet(void **state);
static void test_parse_subunit_v2_common(void **state);
static void test_parse_subunit_v2(void **state);

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
		cmocka_unit_test(test_subunit_version),
		cmocka_unit_test(test_parse_subunit_v2_packet),
		cmocka_unit_test(test_parse_subunit_v2_common),
		cmocka_unit_test(test_parse_subunit_v2),
		cmocka_unit_test(test_parse_subunit_v1_line),
		cmocka_unit_test(test_parse_subunit_v1),
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
    tailq_report *report;
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
    tailq_report *report;
    struct suiteq *suites;

    file = fopen(name, "r");
    if (file == NULL)
    {
        fail();
    }
    suites = parse_testanything(file);
    report = process_file(name);
    fclose(file);
}

/* Basic SubUnit format support */
static void
test_parse_subunit_v2_packet(void **state)
{
    // Packet sample, with test id, runnable set, status=enumeration.
    // Spaces below are to visually break up:
    // signature / flags / length / testid / crc32
    // b3 2901 0c 03666f6f 08555f1b
    // echo 03666f6f | xxd -p -r

    skip();

    subunit_header sample_header = { .signature = 0xb3, .flags = ntohs(0x2901) };
    uint16_t sample_length = 0x0c;
    uint32_t sample_testid = 0x03666f6f;
    uint32_t sample_crc32 = 0x08555f1b;

    char* buf = NULL;
    size_t buf_size = 0;
    tailq_test * test;
    FILE* stream = open_memstream(&buf, &buf_size);
    fwrite(&sample_header, 1, sizeof(sample_header), stream);
    fwrite(&sample_length, 1, sizeof(sample_length), stream);
    fwrite(&sample_testid, 1, sizeof(sample_testid), stream);
    fwrite(&sample_crc32, 1, sizeof(sample_crc32), stream);

    test = read_packet(stream);
    fclose(stream);

    assert_string_equal(test->name, "");

    free(buf);
    free(test);
}


static void
test_subunit_version(void **state)
{
    char *file_subunit_v1 = SAMPLE_FILE_SUBUNIT_V1;
    char *file_subunit_v2 = SAMPLE_FILE_SUBUNIT_V2;

    assert(is_subunit_v2(file_subunit_v1) == 1);
    assert(is_subunit_v2(file_subunit_v2) == 0);
}


static void
test_parse_subunit_v2(void **state)
{
    skip();

    char *name = SAMPLE_FILE_SUBUNIT_V2;
    FILE *file;

    file = fopen(name, "r");
    if (file == NULL)
    {
        fail();
    }
    struct suiteq *suites;
    suites = parse_subunit_v2(file);
    // FIXME: assert(report->format == FORMAT_SUBUNIT_V2);
    fclose(file);
    free(suites);
}

static void
test_parse_subunit_v2_common(void **state)
{
    /* parse via parse() and parse_subunit_v2() and compare structs */

    skip();

    FILE *file;
    char *name = SAMPLE_FILE_SUBUNIT_V2;
    file = fopen(name, "r");
    if (file == NULL)
    {
        fail();
    }
    tailq_report *report;
    struct suiteq *suites;
    suites = parse_subunit_v2(file);
    report  = process_file(name);
    fclose(file);
}

static void
test_parse_subunit_v1(void **state)
{
    char *name = SAMPLE_FILE_SUBUNIT_V1;
    FILE *file;

    file = fopen(name, "r");
    if (file == NULL)
    {
        fail();
    }
    struct suiteq *suites;
    suites = parse_subunit_v1(file);

    fclose(file);
    free(suites);
}

static void
test_parse_subunit_v1_line(void **state)
{
	char *test_sample[] = {
	"test test LABEL",
	"testing test LABEL",
	"test: test LABEL",
	"testing: test LABEL",
	"success test LABEL",
	"success: test LABEL",
	"successful test LABEL",
	"successful: test LABEL",
	"failure: test LABEL",
	"failure: test LABEL DETAILS",
	"error: test LABEL",
	"error: test LABEL DETAILS",
	"skip test LABEL",
	"skip: test LABEL",
	"skip test LABEL DETAILS",
	"skip: test LABEL DETAILS",
	"xfail test LABEL",
	"xfail: test LABEL",
	"xfail test LABEL DETAILS",
	"xfail: test LABEL DETAILS",
	"uxsuccess test LABEL",
	"uxsuccess: test LABEL",
	"uxsuccess test LABEL DETAILS",
	"uxsuccess: test LABEL DETAILS",
	"progress: +10",
	"progress: -14",
	"progress: push",
	"progress: pop",
	"tags: -small +big",
	"time: 2018-09-10 23:59:29Z" };

	char** qq = test_sample;
	struct tailq_test* tl;
	for (int i = 0; i <  sizeof(test_sample)/sizeof(char*); ++i) {
		tl = parse_line_subunit_v1(*qq);
		/* TODO: validate tl struct */
		++qq;
	}
}


/* Basic JUnit format support */
static void
test_parse_junit(void **state)
{
    FILE *file;
    char *name = SAMPLE_FILE_JUNIT;
    struct suiteq *suites;

    file = fopen(name, "r");
    if (file == NULL)
    {
        fail();
    }
    suites = parse_junit(file);
    fclose(file);
}

static void
test_parse_junit_common(void **state)
{
    /* parse via parse() and parse_junit() and compare structs */

    FILE *file;
    char *name = SAMPLE_FILE_JUNIT;
    tailq_report *report;
    struct suiteq *suites;

    file = fopen(name, "r");
    if (file == NULL)
    {
        fail();
    }
    suites = parse_junit(file);
    report = malloc(sizeof(tailq_report));
    if (report == NULL) {
       fail();
    }
    report = process_file(name);
    fclose(file);
}