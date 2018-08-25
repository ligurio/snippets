#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include "parse.h"

char *get_filename_ext(const char *filename) {
    char *dot = strrchr(filename, '.');
    if (!dot || dot == filename) return "";

    return dot + 1;
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

	char *file_ext;
    file_ext = get_filename_ext(basename);
    printf("extension %s\n", file_ext);
    if (strcasecmp("xml", file_ext) == 0) {
       printf("JUnit %s\n", basename);
       parse_junit(file);
    } else if (strcasecmp("tap", file_ext) == 0) {
       printf("TestAnythingProtocol %s\n", basename);
       struct ast_test *tests;
       tests = parse_testanything(file);
       print(stdout, tests);
    } else if (strcasecmp("subunit", file_ext) == 0) {
       printf("SubUnit %s\n", basename);
       printf("TODO\n");
    } else {
       printf("Unknown file format.\n");
	}
    fclose(file);

	return 0;
}
