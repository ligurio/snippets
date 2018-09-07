#include <sys/queue.h>

enum test_format {
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
} tailq_test;

TAILQ_HEAD(testq, tailq_test);

typedef struct tailq_suite {
    const char *name;
    const char *hostname;
    const char *timestamp;
    int n_failures;
    int n_errors;
    double time;
    struct testq *tests;
    TAILQ_ENTRY(tailq_suite) entries;
} tailq_suite;

TAILQ_HEAD(suiteq, tailq_suite);

typedef struct tailq_report {
    enum test_format format;
    struct suiteq *suites;
    time_t ctime;
    TAILQ_ENTRY(tailq_report) entries;
} tailq_report;

TAILQ_HEAD(reportq, tailq_report);

char *get_filename_ext(const char *filename);
enum format detect_format(const char *basename);
tailq_report *process_file(char *path);
tailq_test *make_test(char *name, char *time, char *comment);
const char *status_string(enum test_status status);
const char *format_string(enum test_format format);

void print_single_report(tailq_report *report);
void print_reports(struct reportq *reports_head);
void print_suites(struct suiteq *suites_head);
void print_tests(struct testq *tests_head);

void free_single_report(tailq_report *report);
void free_reports(struct reportq *reports);
void free_suites(struct suiteq *suites);
void free_tests(struct testq *tests);
