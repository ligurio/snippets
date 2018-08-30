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
	STATUS_XFAILURE		/* Subunit */
};

struct test {
	const char *name;
	const char *time;
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

char *get_filename_ext(const char *filename);
enum format detect_format(const char *basename);
report_t *process_file(char *path);
