#ifndef _UTILS_H_
#define _UTILS_H_

#include "test_list.h"

#define MSG_TESTS_NOT_FOUND "No tests found.\n"
#define MSG_TESTS_AVAILABLE "Available tests:\n"

struct test_options {
	char *directory;
	char **exclude;
	int list;
	int timeout;
	char **tests;
	char *report;
};

extern struct test_list *test_discovery(const char *);
extern int print_tests(struct test_list *, FILE *);
extern int run_tests(struct test_list *, const struct test_options,
		const char *, FILE *, FILE *);
extern struct test_list *filter_tests(struct test_list *, char **, int);
extern int test_list_length(struct test_list *tests);

#endif	/* _UTILS_H_ */
