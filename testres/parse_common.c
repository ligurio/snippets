#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#ifndef PARSE_COMMON_H
#define PARSE_COMMON_H
#include "parse_common.h"
#endif /* PARSE_COMMON_H */

#include "parse_junit.h"
#include "parse_testanything.h"

char *get_filename_ext(const char *filename) {
    char *dot = strrchr(filename, '.');
    if (!dot || dot == filename) return "";

    return dot + 1;
}

enum format detect_file_format(const char *basename) {

    char *file_ext;
    file_ext = get_filename_ext(basename);
    printf("extension %s\n", file_ext);

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
    printf("%s\n", path);

    FILE *file;
    file = fopen(path, "r");
    if (!(file)) {
       printf("failed to open file %s", path);
       return NULL;
    }

    enum format f;
    f = detect_file_format(basename);
    report_t * report;
    switch(f) {
        case FORMAT_JUNIT:
	    parse_junit(file);
	    break;
        case FORMAT_TAP13:
	    /* FIXME: return report_t */
	    parse_testanything(file);
	    break;
        case FORMAT_SUBUNIT_V1:
	    //parse_subunit_v2(file);
	    break;
        case FORMAT_SUBUNIT_V2:
	    break;
        case FORMAT_UNKNOWN:
	    break;
    }
    fclose(file);

    return report;
}
