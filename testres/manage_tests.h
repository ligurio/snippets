#ifndef PARSE_COMMON_H
#define PARSE_COMMON_H
#include "parse_common.h"
#endif /* PARSE_COMMON_H */

void print_reports(report_t * report);
void print_suites(suite_t * suite);
void print_tests(test_t * test);

void delete_reports(report_t * report);
void delete_suites(suite_t * suite);
void delete_tests(test_t * test);

//void push_report(report_t * report, enum format format, suite_t * suite);
//void push_suite(suite_t * suite, char* name, test_t * test, int n_failures, int n_errors);
//void push_test(test_t * test, char* name, char* time, enum test_status status);

void push_report(report_t *reports, report_t *report);
void push_suite(suite_t *suites, suite_t *suite);
void push_test(test_t *tests, test_t *test);
