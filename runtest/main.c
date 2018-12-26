#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "utils.h"

#define DEFAULT_DIRECTORY "/usr/src"
#define DEFAULT_TIMEOUT 300

static inline void
print_usage(FILE *stream, char *progname)
{
	fprintf(stream, "Usage: %s [-d directory] [-f filter] [-l list] [-t timeout]"
			" [-o report] [-h]\n", progname);
}

int
main(int argc, char *argv[])
{
	int opt;
	int rc;

	struct test_list *tests = NULL;
	struct test_options opts;

	opts.directory = strdup(DEFAULT_DIRECTORY);
	opts.filter = NULL;
	opts.list = 0;
	opts.timeout = DEFAULT_TIMEOUT;
	opts.report = NULL;

	while ((opt = getopt(argc, argv, "d:f:lt:o:h")) != -1) {
		switch (opt) {
			case 'd':
				free(opts.directory);
				opts.directory = realpath(optarg, NULL);
			break;
			case 'f':
				opts.filter = NULL;
			break;
			case 'l':
				opts.list = 1;
			break;
			case 't':
				opts.timeout = atoi(optarg);
			break;
			case 'h':
				print_usage(stdout, argv[0]);
				exit(0);
			break;
			case 'x':
				free(opts.report);
				opts.report = strdup(optarg);
			break;
			default:
				print_usage(stdout, argv[0]);
				exit(1);
			break;
		}
	}

	fprintf(stdout, "Searching tests in %s\n", opts.directory);
	tests = test_discovery(opts.directory);
	if (tests == NULL || test_list_length(tests) == 0) {
		fprintf(stderr, MSG_TESTS_NOT_FOUND);
		return 1;
	}

	if (opts.list) {
		print_tests(tests, stdout);
		return 0;
	}

	if (opts.filter) {
		filter_tests(tests, opts.filter);
	}

	rc = run_tests(tests, opts, argv[0], stdout, stderr);

	if (opts.report) {
		print_report(tests, opts.report);
		return 0;
	}

	free_tests(tests);

	return rc;
}
