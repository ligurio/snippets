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
#include "parse_junit.h"
#include "parse_subunit_v1.h"
#include "parse_subunit_v2.h"
#include "parse_testanything.h"
#include "sha1.h"

void 
free_reports(struct reportq * reports)
{
	tailq_report *report_item = NULL;
	while ((report_item = TAILQ_FIRST(reports))) {
		if (!TAILQ_EMPTY(report_item->suites)) {
			free_suites(report_item->suites);
		}
		TAILQ_REMOVE(reports, report_item, entries);
		free_report(report_item);
	}
}

void 
free_report(tailq_report *report)
{
	if (!TAILQ_EMPTY(report->suites)) {
		free_suites(report->suites);
	}
	free(report->path);
	free(report->id);
	free(report);
}

void 
free_suites(struct suiteq * suites)
{
	tailq_suite *suite_item = NULL;
	while ((suite_item = TAILQ_FIRST(suites))) {
		TAILQ_REMOVE(suites, suite_item, entries);
		free_suite(suite_item);
	}
}

void 
free_suite(tailq_suite * suite)
{
	if (suite->name) {
	   free((char*)suite->name);
        }
	if (suite->hostname) {
	   free((char*)suite->hostname);
        }
	if (suite->timestamp) {
	   free((char*)suite->timestamp);
        }
	if (!TAILQ_EMPTY(suite->tests)) {
		free_tests(suite->tests);
	}

	free(suite);
}

void 
free_tests(struct testq * tests)
{
	tailq_test *test_item;
	while ((test_item = TAILQ_FIRST(tests))) {
		TAILQ_REMOVE(tests, test_item, entries);
		free_test(test_item);
	}
}

void 
free_test(tailq_test * test)
{
	if (test->name) {
	   free((char*)test->name);
        }
	if (test->time) {
	   free((char*)test->time);
        }
	if (test->comment) {
	   free((char*)test->comment);
        }
	if (test->error) {
	   free((char*)test->error);
        }
	if (test->system_out) {
	   free((char*)test->system_out);
        }
	if (test->system_err) {
	   free((char*)test->system_err);
        }
	free(test);
}

char *
get_filename_ext(const char *filename)
{
	char *dot = strrchr(filename, '.');
	if (!dot || dot == filename)
		return (char *) NULL;

	return dot + 1;
}

enum test_format 
detect_file_format(char *path)
{
	char *file_ext;
	file_ext = get_filename_ext(basename(path));

	if (strcasecmp("xml", file_ext) == 0) {
		return FORMAT_JUNIT;
	} else if (strcasecmp("tap", file_ext) == 0) {
		return FORMAT_TAP13;
	} else if (strcasecmp("subunit", file_ext) == 0) {
		if (is_subunit_v2(path) == 0) {
		   return FORMAT_SUBUNIT_V2;
		} else {
		   return FORMAT_SUBUNIT_V1;
		}
	} else {
		return FORMAT_UNKNOWN;
	}
}

unsigned char *digest_to_str(unsigned char *str, unsigned char digest[], unsigned int n) {
	int r;
	if (n == 0) return 0;
	if (n == 1) r = sprintf((char*)str, "%x", digest[0]);
	else        r = sprintf((char*)str, "%x", digest[0]);
	digest_to_str(str + r, digest + 1, n - 1);

	return str;
}

tailq_report *
process_file(char *path)
{
	FILE *file;
	file = fopen(path, "r");
	if (file == NULL) {
		printf("failed to open file %s\n", path);
		return NULL;
	}
	tailq_report *report = NULL;
	report = calloc(1, sizeof(tailq_report));
	if (report == NULL) {
		perror("malloc failed");
		fclose(file);
		return NULL;
	}
	enum test_format format;
	format = detect_file_format(path);
	switch (format) {
	case FORMAT_JUNIT:
		report->format = FORMAT_JUNIT;
		report->suites = parse_junit(file);
		break;
	case FORMAT_TAP13:
		report->format = FORMAT_TAP13;
		report->suites = parse_testanything(file);
		break;
	case FORMAT_SUBUNIT_V1:
		report->format = FORMAT_SUBUNIT_V1;
		report->suites = parse_subunit_v1(file);
		break;
	case FORMAT_SUBUNIT_V2:
		report->format = FORMAT_SUBUNIT_V2;
		report->suites = parse_subunit_v2(file);
		break;
	case FORMAT_UNKNOWN:
		break;
	}
	fclose(file);

	struct stat sb;
	stat(path, &sb);
	report->ctime = sb.st_ctime;
	report->path = (unsigned char*)strdup(path);

	int length = 20;
	unsigned char digest[length];
	SHA1_CTX ctx;
	SHA1Init(&ctx);
	SHA1Update(&ctx, report->path, strlen(path));
	SHA1Final(digest, &ctx);

	report->id = calloc(length, sizeof(unsigned char*));
	digest_to_str(report->id, digest, length);

	return report;
}

struct tailq_report *is_report_exists(struct reportq *reports, const char* report_id) {

	tailq_report *report_item = NULL;
	TAILQ_FOREACH(report_item, reports, entries) {
	    if (strcmp(report_id, (char*)report_item->id) == 0) {
		break;
	    }
	}

	return report_item;
}
