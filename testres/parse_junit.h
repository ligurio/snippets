#ifndef PARSE_COMMON_H
#define PARSE_COMMON_H
#include "parse_common.h"
#endif /* PARSE_COMMON_H */

//report_t *parse_junit(FILE *f);	// REMOVE
TAILQ_HEAD(, tailq_suite) parse_junit(FILE *f);
