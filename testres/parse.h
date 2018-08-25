#include "parse_testanything.h"
#include "parse_junit.h"

enum test_status {
	TEST_OK,			/* TestAnythingProtocol	*/
	TEST_NOTOK,			/* TestAnythingProtocol	*/
	TEST_MISSING,		/* TestAnythingProtocol	*/
	TEST_TODO,			/* TestAnythingProtocol	*/
	TEST_SKIP,			/* TestAnythingProtocol	*/

	TEST_UNDEFINED,		/* Subunit */
	TEST_ENUMERATION,	/* Subunit */
	TEST_INPROGRESS,	/* Subunit */
	TEST_SUCCESS,		/* Subunit */
	TEST_UXSUCCESS,		/* Subunit */
	TEST_SKIPPED,		/* Subunit */
	TEST_FAILED,		/* Subunit */
	TEST_XFAILURE		/* Subunit */
};

struct test {
	const char *name;
	const char *time;
	enum test_status status;
	struct test *next;
};

typedef struct test test;

struct suite {
	const char *name;
	const char *hostname;
	const char *timestamp;
    double time;
    int n_failures;
    int n_errors;
	struct test *test;
	struct suite *next;
};

typedef struct suite suite;

struct report {
	struct suite *suite;
	struct report *next;
};

typedef struct report report;

char *get_filename_ext(const char *filename);
int process_file(const char *path, const char *name);
