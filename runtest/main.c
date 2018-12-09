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
	fprintf(stream, "Usage: %s [-d directory] [-e exclude] [-l list] [-t timeout]"
			" [-o report] [-h] [test1 test2 ...]\n", progname);
}

int
main(int argc, char *argv[])
{
	int opt;
	int test_num = 0;
	int i;
	int rc;
	int test_exclude_num = 0;
	char *c, *tok;

	struct test_list *tests = NULL, *run = NULL;
	struct test_options opts;

	opts.directory = strdup(DEFAULT_DIRECTORY);
	opts.exclude = NULL;
	opts.list = 0;
	opts.timeout = DEFAULT_TIMEOUT;
	opts.tests = NULL;
	opts.report = NULL;

	while ((opt = getopt(argc, argv, "d:e:lt:o:h")) != -1) {
		switch (opt) {
			case 'd':
				free(opts.directory);
				opts.directory = realpath(optarg, NULL);
			break;
			case 'e':
				c = optarg;
				test_exclude_num = 1;

				while (*c) {
					if (isspace(*c))
						test_exclude_num++;
					c++;
				}

				opts.exclude = malloc(test_exclude_num * sizeof(char));

				i = 0;
				tok = strtok_r(optarg, " ", &c);
				opts.exclude[i] = strdup(tok);
				i++;
				while ((tok = strtok_r(NULL, " ", &c)) != NULL) {
					opts.exclude[i] = strdup(tok);
					i++;
				}
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

	test_num = argc - optind;
	if (test_num > 0) {
		size_t size = test_num * sizeof(char *);
		opts.tests = calloc(1, size);

		for (i = 0; i < test_num; i++) {
			opts.tests[i] = strdup(argv[argc - test_num + i]);
		}
	}

	tests = test_discovery(opts.directory);
	if (tests == NULL || test_list_length(tests) == 0) {
		fprintf(stderr, MSG_TESTS_NOT_FOUND);
		return 1;
	}

	if (opts.list) {
		print_tests(tests, stdout);
		return 0;
	}

/*
	run = tests;
	if (test_num > 0) {
		for (i = 0; i < test_num; i++) {
			if (test_list_search(tests, opts.tests[i]) == NULL) {
				fprintf(stderr, "%s test isn't available.\n",
					opts.tests[i]);
				return 1;
			}
		}

		run = filter_tests(head, opts.tests, test_num);
		free_tests(tests);
	}

	TAILQ_FOREACH(test, tests, entries) {
	    if (strcmp(report_id, (char*)report_item->id) == 0) {
		break;
	    }
	}
*/

	/*
	for (i = 0; i < test_exclude_num; i++)
		test_list_remove(run, opts.exclude[i], 1);
	*/

	rc = run_tests(run, opts, argv[0], stdout, stderr);

	free_tests(run);

	return rc;
}
