#include <fcntl.h>
#include <stdio.h>
#include <string.h>

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

report_t *process_file(const char *dirname, const char *basename) {

    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dirname, basename);

    FILE *file;
    file = fopen(path, "r");
    if (!(file)) {
       printf("failed to open file %s\n", path);
       return NULL;
    }

    enum format f;
    f = detect_file_format(basename);
    report_t * report = NULL;
    switch(f) {
        case FORMAT_JUNIT:
	    report = parse_junit(file);
	    break;
        case FORMAT_TAP13:
	    report = parse_testanything(file);
	    break;
        case FORMAT_SUBUNIT_V1:
	    /* TODO */
	    break;
        case FORMAT_SUBUNIT_V2:
	    report = parse_subunit_v2(file);
	    break;
        case FORMAT_UNKNOWN:
	    break;
    }
    fclose(file);

    return report;
}
