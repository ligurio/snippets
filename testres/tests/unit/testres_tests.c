#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>
#include <assert.h>
#include <arpa/inet.h>

#include "parse_common.h"
#include "parse_junit.h"
#include "parse_testanything.h"
#include "parse_subunit_v1.h"
#include "parse_subunit_v2.h"
#include "sha1.h"
#include "cmp.h"

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

static void test_sha1(void **state);
static void test_cmp(void **state);

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
		cmocka_unit_test(test_sha1),
		cmocka_unit_test(test_cmp),
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

static void
test_sha1(void **state)
{

    struct {
      char *word;
      char *digest;
      } tests[] = {
        /* Test Vectors (from FIPS PUB 180-1) */
        { "abc", "a9993e364706816aba3e25717850c26c9cd0d89d" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1" },
        { NULL, NULL },
    };

    int i, length = 20;
    unsigned char digest[length];
    char *str = calloc(length, sizeof(unsigned char*));
    for (i = 0; tests[i].word != NULL; i++) {
	const char *word = tests[i].word;
        SHA1_CTX ctx;
        SHA1Init(&ctx);
        SHA1Update(&ctx, word, strlen(word));
        SHA1Final(digest, &ctx);
        if (digest_to_str(str, digest, length) != tests[i].digest) {
           fail();
        }
    }
    free(str);
}

static void
test_cmp(void **state)
{

    struct {
          char *word1;
          char *word2;
          int distance;
      } tests[] = {
          /* It should work. */
          { "", "a", 1 },
          { "a", "", 1 },
          { "", "", 0 },
          { "levenshtein", "levenshtein", 0 },
          { "sitting", "kitten", 3 },
          { "gumbo", "gambol", 2 },
          { "saturday", "sunday", 3 },
              
          /* It should match case sensitive. */
          { "DwAyNE", "DUANE", 2 },
          { "dwayne", "DuAnE", 5 },
          
          /* It not care about parameter ordering. */
          { "aarrgh", "aargh", 1 },
          { "aargh", "aarrgh", 1 },
          
          /* Some tests form `hiddentao/fast-levenshtein`. */
          { "a", "b", 1 },
          { "ab", "ac", 1 },
          { "ac", "bc", 1 },
          { "abc", "axc", 1 },
          { "xabxcdxxefxgx", "1ab2cd34ef5g6", 6 },
          { "xabxcdxxefxgx", "abcdefg", 6 },
          { "javawasneat", "scalaisgreat", 7 },
          { "example", "samples", 3 },
          { "sturgeon", "urgently", 6 },
          { "levenshtein", "frankenstein", 6 },
          { "distance", "difference", 5 },
          { NULL, NULL, 0 },
    };

    const char *word1;
    const char *word2;

    int i, d;
    for (i = 0; tests[i].word1 != NULL; i++) {
         /* printf("===> '%s' and '%s'\n", tests[i].word1, tests[i].word2); */
         word1 = tests[i].word1;
         word2 = tests[i].word2;
         d = distance(word1, strlen(word1), word2, strlen(word2));
         assert(d == tests[i].distance);
    }
}
