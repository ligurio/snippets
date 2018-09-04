#include <sys/queue.h>

enum format {
	FORMAT_UNKNOWN,
	FORMAT_TAP13,
	FORMAT_JUNIT,
	FORMAT_SUBUNIT_V1,
	FORMAT_SUBUNIT_V2
};

enum test_status {
	STATUS_OK,		/* TestAnythingProtocol	*/
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
	STATUS_PASS		/* JUnit */
};

typedef struct tailq_test {
    const char *name;
    const char *time;
    const char *comment;
    enum test_status status;
    TAILQ_ENTRY(tailq_test) entries;
    TAILQ_HEAD(, tailq_test) head;
} tailq_test;

typedef struct tailq_suite {
    const char *name;
    const char *hostname;
    const char *timestamp;
    int n_failures;
    int n_errors;
    double time;
    TAILQ_HEAD(, tailq_test) testq;
    TAILQ_ENTRY(tailq_suite) entries;
    TAILQ_HEAD(, tailq_suite) head;
} tailq_suite;

typedef struct tailq_report {
    enum format format;
    tailq_suite *suites;
    TAILQ_HEAD(, tailq_suite) suiteq;
    TAILQ_ENTRY(tailq_report) entries;
    TAILQ_HEAD(, tailq_report) head;
} tailq_report;

char *get_filename_ext(const char *filename);
enum format detect_format(const char *basename);
tailq_report *process_file(char *path);
tailq_test *make_test(char *name, char *time, char *comment);
const char *status_string(enum test_status status);
void print_single_report(tailq_report *report);
void print_reports(tailq_report *reports_head);
void print_suites(tailq_suite *suites_head);
void print_tests(tailq_test *tests_head);
