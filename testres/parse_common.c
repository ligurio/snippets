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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

#ifndef PARSE_COMMON_H
#define PARSE_COMMON_H
#include "parse_common.h"
#endif /* PARSE_COMMON_H */

#include "parse_junit.h"
#include "parse_testanything.h"
#include "parse_subunit_v2.h"

void print_single_report(tailq_report *report) {
  tailq_suite *suite_item;
  /* FIXME: print_suites(report->suiteq); */
}

void print_reports(tailq_report *reports_head) {
  tailq_report *report_item;
  TAILQ_FOREACH(report_item, &reports_head->head, entries) {
      printf("report format %d\n", report_item->format);
      print_single_report(report_item);
  }
}

void print_suites(tailq_suite *suites_head) {

  tailq_suite *suite_item;
  TAILQ_FOREACH(suite_item, &suites_head->head, entries) {
      printf("TESTSUITE %10s ", suite_item->name);
      printf("(%d failures, %d errors)\n", suite_item->n_failures, suite_item->n_errors);
  }
}

void print_tests(tailq_test *tests_head) {

  tailq_test *test_item;
  TAILQ_FOREACH(test_item, &tests_head->head, entries) {
      printf("\t%10s ", status_string(test_item->status));
      printf("%10s ", test_item->name);
      if (test_item->time != NULL) {
         printf("(%5ss)\n", test_item->time);
      } else {
         printf("\n");
      }
      if (test_item->comment != NULL) {
         printf("Comment: %5s\n", test_item->comment);
      }
  }
}

const char *
status_string(enum test_status status)
{
	switch (status) {
	case STATUS_OK:          return "STATUS_OK";
	case STATUS_NOTOK:       return "STATUS_NOTOK";
	case STATUS_MISSING:     return "STATUS_MISSING";
	case STATUS_TODO:        return "STATUS_TODO";
	case STATUS_SKIP:        return "STATUS_SKIP";
	case STATUS_UNDEFINED:   return "STATUS_UNDEFINED";
	case STATUS_ENUMERATION: return "STATUS_ENUMERATION";
	case STATUS_INPROGRESS:  return "STATUS_INPROGRESS";
	case STATUS_SUCCESS:     return "STATUS_SUCCESS";
	case STATUS_UXSUCCESS:   return "STATUS_UXSUCCESS";
	case STATUS_SKIPPED:     return "STATUS_SKIPPED";
	case STATUS_FAILED:      return "STATUS_FAILED";
	case STATUS_XFAILURE:    return "STATUS_XFAILURE";
	case STATUS_ERROR:       return "STATUS_ERROR";
	case STATUS_FAILURE:     return "STATUS_FAILURE";
	case STATUS_PASS:        return "STATUS_PASS";

	default:
		return "STATUS_UNKNOWN";
	}
}

char *get_filename_ext(const char *filename) {
    char *dot = strrchr(filename, '.');
    if (!dot || dot == filename)
        return "";

    return dot + 1;
}

enum format detect_file_format(const char *basename) {

    char *file_ext;
    file_ext = get_filename_ext(basename);

    if (strcasecmp("xml", file_ext) == 0) {
       return FORMAT_JUNIT;
    } else if (strcasecmp("tap", file_ext) == 0) {
       return FORMAT_TAP13;
    } else if (strcasecmp("subunit", file_ext) == 0) {
       return FORMAT_SUBUNIT_V2;
    } else {
       return FORMAT_UNKNOWN;
    }
}

tailq_report *process_file(char *path) {

    FILE *file;
    file = fopen(path, "r");
    if (file == NULL) {
       printf("failed to open file %s\n", path);
       return NULL;
    }

    tailq_report *report = NULL;
    if (!(report = malloc(sizeof(tailq_report)))) {
       perror("malloc failed");
    }
    memset(report, 0, sizeof(tailq_report));

    enum format f;
    f = detect_file_format(basename(path));
    switch(f) {
      case FORMAT_JUNIT:
        report->format = FORMAT_JUNIT;
        report->suites = parse_junit(file);
	break;
      case FORMAT_TAP13:
        report->format = FORMAT_TAP13;
        report->suites = parse_testanything(file);
	break;
      case FORMAT_SUBUNIT_V1:
	/* TODO */
        report->format = FORMAT_SUBUNIT_V1;
	break;
      case FORMAT_SUBUNIT_V2:
        report->format = FORMAT_SUBUNIT_V2;
        report->suites = parse_subunit_v2(file);
	break;
      case FORMAT_UNKNOWN:
	break;
    }
    fclose(file);

    return report;
}
