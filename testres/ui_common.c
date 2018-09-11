#include <stdio.h>

#include "ui_common.h"

void 
print_html_headers(void)
{
	printf("Content-Type: text/plain;charset=utf-8\n\n");
}

void 
print_html_single_report(struct tailq_report * report)
{
	printf("\nTEST REPORT (%s)\n", format_string(report->format));
	char buffer[80] = "";
	struct tm *info = localtime(&report->ctime);
	strftime(buffer, 80, "%x - %I:%M%p", info);
	printf("CREATED ON: %s\n", buffer);
	if (!TAILQ_EMPTY(report->suites)) {
		print_html_suites(report->suites);
	}
}

void 
print_html_suites(struct suiteq * suites)
{

	tailq_suite *suite_item;
	TAILQ_FOREACH(suite_item, suites, entries) {
		if (suite_item->name == (char *) NULL) {
			printf("%10s ", suite_item->name);
		} else {
			printf("%10s ", "noname");
		}
		printf("(%d failures, %d errors) ", suite_item->n_failures, suite_item->n_errors);
		printf("%5f ", suite_item->time);
		if (suite_item->timestamp != (char *) NULL) {
			printf("%10s ", suite_item->timestamp);
		}
		if (suite_item->hostname != (char *) NULL) {
			printf("%10s ", suite_item->hostname);
		}
		printf("\n");
		if (!TAILQ_EMPTY(suite_item->tests)) {
			print_html_tests(suite_item->tests);
		}
	}
}

void 
print_html_tests(struct testq * tests)
{
	tailq_test *test_item;
	TAILQ_FOREACH(test_item, tests, entries) {
		printf("\t%10s ", test_item->name);
		printf("%10s ", status_string(test_item->status));
		if (test_item->time != (char *) NULL) {
			printf("(%5ss) ", test_item->time);
		}
		if (test_item->comment != NULL) {
			printf("Comment: %5s", test_item->comment);
		}
		printf("\n");
	}
}
