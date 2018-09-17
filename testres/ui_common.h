#ifndef PARSE_COMMON_H
#define PARSE_COMMON_H
#include "parse_common.h"
#endif				/* PARSE_COMMON_H */

char version[1024];

void print_html_headers(void);
void print_html_footer(void);
void print_html_reports(struct reportq * reports);
void print_html_report(struct tailq_report *report);
void print_html_suites(struct suiteq * suites);
void print_html_tests(struct testq * tests);
