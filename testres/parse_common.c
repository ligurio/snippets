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

report_t *process_file(char *path) {

    FILE *file;
    file = fopen(path, "r");
    if (file == NULL) {
       printf("failed to open file %s\n", path);
       return NULL;
    }

    enum format f;
    f = detect_file_format(basename(path));
    report_t *report = NULL;
    suite_t *suites = NULL;
    if (!(report = malloc(sizeof(report_t)))) {
       return NULL;
    }
    memset(report, 0, sizeof(report_t));
    switch(f) {
      case FORMAT_JUNIT:
	    parse_junit(file);
        report->format = FORMAT_JUNIT;
        report->suite = suites;
	    break;
      case FORMAT_TAP13:
	    parse_testanything(file);
        report->format = FORMAT_TAP13;
        report->suite = suites;
	    break;
      case FORMAT_SUBUNIT_V1:
	    /* TODO */
        report->format = FORMAT_SUBUNIT_V1;
	    break;
      case FORMAT_SUBUNIT_V2:
	    parse_subunit_v2(file);
        report->format = FORMAT_SUBUNIT_V2;
        report->suite = suites;
	    break;
      case FORMAT_UNKNOWN:
	    break;
    }
    fclose(file);

    return report;
}
