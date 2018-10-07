/*
 * Copyright © 2018 Sergey Bronnikov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "parse_common.h"
#include "ui_console.h"
#include "ui_common.h"

void 
print_report(struct tailq_report * report)
{
	printf("\nTEST REPORT (%s)\n", format_string(report->format));
	char buffer[80] = "";
	struct tm *info = localtime(&report->ctime);
	strftime(buffer, 80, "%x - %I:%M%p", info);
	printf("CREATED ON: %s\n", buffer);
	printf("FILE: %s\n", report->path);
	/* printf("ID: %s\n", report->id); */
	if (!TAILQ_EMPTY(report->suites)) {
		print_suites(report->suites);
	}
}

void 
print_reports(struct reportq * reports)
{
	tailq_report *report_item = NULL;
	TAILQ_FOREACH(report_item, reports, entries) {
		print_report(report_item);
	}
}

void 
print_suites(struct suiteq * suites)
{
	tailq_suite *suite_item = NULL;
	TAILQ_FOREACH(suite_item, suites, entries) {
		const char* name = NULL;
		if (suite_item->name != (char *)NULL) {
			name = suite_item->name;
		} else {
			/* FIXME	*/
			name = "unknown name";
		}
		printf("SUITE: %10s ", name);
		/* TODO: print testsuite summary  */
		printf("(%d failures, %d errors)\n", suite_item->n_failures, suite_item->n_errors);
		printf("TOTAL DURATION: %5f ", suite_item->time);
		if (suite_item->timestamp != (char *)NULL) {
			printf("TIMESTAMP: %10s ", suite_item->timestamp);
		}
		if (suite_item->hostname != (char *)NULL) {
			printf("HOSTNAME %10s ", suite_item->hostname);
		}
		printf("\n");
		if (!TAILQ_EMPTY(suite_item->tests)) {
			print_tests(suite_item->tests);
		}
	}
}

void 
print_tests(struct testq * tests)
{
	tailq_test *test_item = NULL;
	TAILQ_FOREACH(test_item, tests, entries) {
		printf("\tTEST: %10.50s ", test_item->name);
		printf("%10.50s ", status_string(test_item->status));
		if (test_item->time != (char *)NULL) {
			printf("(%5ss) ", test_item->time);
		}
		if (test_item->comment != (char *)NULL) {
			printf("Comment: %5s", test_item->comment);
		}
		printf("\n");
	}
}
