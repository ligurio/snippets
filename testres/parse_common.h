#include <sys/queue.h>

enum format {
	FORMAT_UNKNOWN,
	FORMAT_TAP13,
	FORMAT_JUNIT,
	FORMAT_SUBUNIT_V1,
	FORMAT_SUBUNIT_V2
};

enum test_status {
	STATUS_OK,			/* TestAnythingProtocol	*/
	STATUS_NOTOK,		/* TestAnythingProtocol	*/
	STATUS_MISSING,		/* TestAnythingProtocol	*/
	STATUS_TODO,		/* TestAnythingProtocol	*/
	STATUS_SKIP,		/* TestAnythingProtocol	*/

	STATUS_UNDEFINED,	/* Subunit */
	STATUS_ENUMERATION,	/* Subunit */
	STATUS_INPROGRESS,	/* Subunit */
	STATUS_SUCCESS,		/* Subunit */
	STATUS_UXSUCCESS,	/* Subunit */
	STATUS_SKIPPED,		/* Subunit */
	STATUS_FAILED,		/* Subunit */
	STATUS_XFAILURE,	/* Subunit */

	STATUS_ERROR,		/* JUnit */
	STATUS_FAILURE,		/* JUnit */
	STATUS_PASS			/* JUnit */
};

struct test {
	const char *name;
	const char *time;
	const char *comment;
	enum test_status status;
	struct test *next;
};

typedef struct test test_t;

struct suite {
    const char *name;
    const char *hostname;
    const char *timestamp;
    int n_failures;
    int n_errors;
    double time;
    struct test *test;
    struct suite *next;
};

typedef struct suite suite_t;

struct report {
    enum format format;
    struct suite *suite;
    struct report *next;
};

typedef struct report report_t;

struct tailq_test {
    const char *name;
    const char *time;
    const char *comment;
    enum test_status status;
    TAILQ_ENTRY(tailq_test) entries;
};

typedef struct tailq_test tailq_test;

struct tailq_suite {
    const char *name;
    const char *hostname;
    const char *timestamp;
    int n_failures;
    int n_errors;
    double time;
    tailq_test *tests;
    TAILQ_ENTRY(tailq_suite) entries;
};

typedef struct tailq_suite tailq_suite;

struct tailq_report {
    enum format format;
    tailq_suite *suites;
    TAILQ_ENTRY(tailq_report) entries;
};

typedef struct tailq_report tailq_report;

char *get_filename_ext(const char *filename);
enum format detect_format(const char *basename);
tailq_report *process_file(char *path);
