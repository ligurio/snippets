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

#include <math.h>

#include "parse_common.h"
#include "ui_console.h"
#include "ui_common.h"

void
print_report(struct tailq_report * report)
{
	printf("\nTEST REPORT (%s)\n", format_string(report->format));
	printf("ID: %s\n", report->id);
	char buffer[80] = "";
	struct tm *info = localtime(&report->ctime);
	strftime(buffer, 80, "%c", info);
	printf("CREATED ON: %s\n", buffer);
	printf("FILE: %s\n", report->path);
	if (!TAILQ_EMPTY(report->suites)) {
		print_suites(report->suites);
	} else {
		printf("None suites.\n");
	}
}

void
print_report_summary(struct tailq_report * report)
{
	char buffer[80] = "";
	struct tm *info = localtime(&report->ctime);
	strftime(buffer, 80, "%D %H:%M", info);
	printf("%s", buffer);
	printf(" %5d %5d %5d",
				num_by_status_class(report, STATUS_CLASS_PASS),
				num_by_status_class(report, STATUS_CLASS_FAIL),
				num_by_status_class(report, STATUS_CLASS_SKIP));
	printf(" %-40s\n", report->path);
}

void
print_reports(struct reportq * reports)
{
	/* TODO: sort reports by date */
	tailq_report *report_item = NULL;
	printf("-------------------------------------------------------------\n");
	printf("DATE            PASS  FAIL  SKIP FILE\n");
	printf("-------------------------------------------------------------\n");
	TAILQ_FOREACH(report_item, reports, entries) {
	   print_report_summary(report_item);
	}
}

void
print_suites(struct suiteq * suites)
{
	tailq_suite *suite_item = NULL;
	TAILQ_FOREACH(suite_item, suites, entries) {
		const char *name = "noname";
		if (suite_item->name != (char *)NULL) {
			name = suite_item->name;
		}
		printf("\nSUITE: %s", name);
		if (suite_item->timestamp != (char *)NULL) {
			printf(" (%s)", suite_item->timestamp);
		}
		printf("\n");
		if (!TAILQ_EMPTY(suite_item->tests)) {
			print_tests(suite_item->tests);
		} else {
			printf("None tests.\n");
		}
	}
}

void format_sec(double sec, char *out) {
	if (sec > 3600) {
	    sec = round(sec);
	    int h = sec / 3600;
	    int m = (sec - h * 3600) / 60;
	    int s = sec - h * 3600 - m * 60;
	    snprintf(out, 16, "%dh%dm%ds", h, m, s);
	}
	else if (sec > 60) {
	    int m = sec / 60.0;
	    int s = sec - 60.0 * m;
	    snprintf(out, 16, "%dm %ds", m, s);
	}
	else if (sec > 1)
	    snprintf(out, 16, "%7.0fs", round(sec));
	else if (sec > 0.001)
	    snprintf(out, 16, "%7.0fms", round(sec * 1000.0));
	else if (sec > 0.001 * 0.001)
	    snprintf(out, 16, "%7.0fµs", round(sec * 1000.0 * 1000.0));
	else if (sec > 0.001 * 0.001 * 0.001)
	    snprintf(out, 16, "%7.0fns", round(sec * 1000.0 * 1000.0 * 1000.0));
}

void
print_tests(struct testq * tests)
{
	tailq_test *test_item = NULL;
	TAILQ_FOREACH(test_item, tests, entries) {
		printf("\t%4.4s ", format_status(test_item->status));
		if (test_item->time != NULL) {
			char buf[16];
			format_sec(atof(test_item->time), buf);
			printf("%s ", buf);
		}
		printf("%s\n", test_item->name);
	}
}
