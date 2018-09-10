#include <stdint.h>

#ifndef PARSE_COMMON_H
#define PARSE_COMMON_H
#include "parse_common.h"
#endif /* PARSE_COMMON_H */

enum directive {
	DIR_TEST,
	DIR_SUCCESS,
	DIR_FAILURE,
	DIR_ERROR,
	DIR_SKIP,
	DIR_XFAIL,
	DIR_UXSUCCESS,
	DIR_PROGRESS,
	DIR_TAGS,
	DIR_TIME,
	DIR_UNKNOWN
};

struct testline {
	enum directive dir;
	char* label;
};

struct testline* parse_line_subunit_v1(char* string);
struct suiteq* parse_subunit_v1(FILE* stream);
struct tm* parse_iso8601_time(char* date_str, char* time_str);
enum directive resolve_directive(char* string);
const char* directive_string(enum directive dir);
void read_tok();
