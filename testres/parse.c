#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include "parse.h"

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
       return FORMAT_SUBUNITV2;
    } else {
       return FORMAT_UNKNOWN;
	}
}

int process_file(const char *dirname, const char *basename) {

    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dirname, basename);
    printf("%s\n", path);

    FILE *file;
    file = fopen(path, "r");
    if (!(file)) {
       printf("failed to open file %s", path);
       return 1;
    }

	enum format f;
	f = detect_file_format(basename);
	switch(f) {
		case FORMAT_JUNIT:
			printf("JUnit %s\n", basename);
			parse_junit(file);
			break;
		case FORMAT_TAP13:
			printf("TestAnythingProtocol %s\n", basename);
			struct ast_test *tests;
			tests = parse_testanything(file);
			print(stdout, tests);
			break;
		case FORMAT_SUBUNITV1:
			printf("SubUnit v1 %s\n", basename);
			printf("TODO\n");
			break;
		case FORMAT_SUBUNITV2:
			printf("SubUnit v2 %s\n", basename);
			printf("TODO\n");
			break;
		default:
			printf("Unknown file format.\n");
	}

    fclose(file);

	return 0;
}
