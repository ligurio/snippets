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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#ifndef PARSE_COMMON_H
#define PARSE_COMMON_H
#include "parse_common.h"
#endif /* PARSE_COMMON_H */

#include "parse_junit.h"
#include "parse_testanything.h"
#include "parse_subunit_v2.h"

void print_single_report(struct tailq_report *report) {
  printf("\nTEST REPORT (%s)\n", format_string(report->format));

  char buffer[80];
  struct tm *info = localtime(report->ctime);
  strftime(buffer, 1024, "%x - %I:%M%p", info);
  printf("CREATED: %s\n", buffer);
  print_suites(report->suites);
}

void print_reports(struct reportq *reports) {
  tailq_report *report_item;
  TAILQ_FOREACH(report_item, reports, entries) {
      print_single_report(report_item);
  }
}

void print_suites(struct suiteq *suites) {

  tailq_suite *suite_item;
  TAILQ_FOREACH(suite_item, suites, entries) {
      printf("%10s ", suite_item->name);
      printf("(%d failures, %d errors) ", suite_item->n_failures, suite_item->n_errors);
      printf("%5f ", suite_item->time);
      if (suite_item->timestamp != (char*)NULL) {
         printf("%10s ", suite_item->timestamp);
      }
      if (suite_item->hostname != (char*)NULL) {
         printf("%10s ", suite_item->hostname);
      }
      printf("\n");
      // FIXME: print_tests(suite_item->tests);
  }
}

void print_tests(struct testq *tests) {

  tailq_test *test_item;
  TAILQ_FOREACH(test_item, tests, entries) {
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

const char *format_string(enum test_format format) {

	switch (format) {
	case FORMAT_TAP13:       return "FORMAT_TAP13";
	case FORMAT_JUNIT:       return "FORMAT_JUNIT";
	case FORMAT_SUBUNIT_V1:  return "FORMAT_SUBUNIT_V1";
	case FORMAT_SUBUNIT_V2:  return "FORMAT_SUBUNIT_V2";
	case FORMAT_UNKNOWN:     return "FORMAT_UNKNOWN";

	default:
	    return "FORMAT_UNKNOWN";
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

/*
time_t *report_ctime(char *filename) {
    struct stat sb;
    stat(filename, &sb);

    return &sb.st_ctime;
}
*/

char *get_filename_ext(const char *filename) {
    char *dot = strrchr(filename, '.');
    if (!dot || dot == filename)
        return (char *)NULL;

    return dot + 1;
}

enum test_format detect_file_format(const char *basename) {

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

    enum test_format format;
    format = detect_file_format(basename(path));
    switch(format) {
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
        //report->suites = parse_subunit_v2(file);
	break;
      case FORMAT_UNKNOWN:
	break;
    }

    fclose(file);
    struct stat sb;
    stat(path, &sb);
    report->ctime = &sb.st_ctime;

    return report;
}
