#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void print_reports(report_t * report) {
    report_t * current = report;
    printf("+++ report +++\n");
    while (current != NULL) {
        printf("format: %d\n", current->format);
        if (current->suite != NULL)
           print_suites(current->suite);
        current = current->next;
    }
}

void print_suites(suite_t * suite) {
    suite_t * current = suite;
    printf("\t+++ suite +++\n");
    while (current != NULL) {
        printf("\tn_errors %d\n", current->n_errors);
        printf("\tn_failures %d\n", current->n_failures);
        printf("\tname %s\n", current->name);
        printf("\thostname %s\n", current->hostname);
        printf("\ttimestamp %s\n", current->timestamp);
        printf("\ttime %f\n", current->time);
        if (current->test != NULL)
           print_tests(current->test);
        current = current->next;
    }
}

void print_tests(test_t * test) {
    test_t * current = test;
    printf("\t\t+++ test +++\n");
    while (current != NULL) {
        printf("\t\tstatus: %d\n", current->status);
        printf("\t\tname: %s\n", current->name);
        printf("\t\ttime: %s\n", current->time);
        current = current->next;
    }
}

void delete_tests(test_t * test) {
    test_t * next;
    test_t * current = test;
    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
        printf("removed test\n");
    }
    test = NULL;
}

void delete_suites(suite_t * suite) {
    suite_t * next;
    suite_t * current = suite;
    while (current != NULL) {
        if (current->test != NULL)
           delete_tests(current->test);
        next = current->next;
        free(current);
        current = next;
        printf("removed suite\n");
    }
    suite = NULL;
}

void delete_reports(report_t * report) {
    report_t * next;
    report_t * current = report;
    while (current != NULL) {
        if (current->suite != NULL)
           delete_suites(current->suite);
        next = current->next;
        free(current);
        current = next;
        printf("removed report\n");
    }
    report = NULL;
}

void push_report(report_t * report, enum format format, suite_t * suite) {
    report_t * current = report;

    while (current->next != NULL) {
        current = current->next;
    }
    current->next = malloc(sizeof(report_t));
    current->next->format = format;
    current->next->suite = suite;
    current->next->next = NULL;
}

void push_suite(suite_t * suite, char* name, test_t * test, int n_failures, int n_errors) {
    suite_t * current = suite;

    while (current->next != NULL) {
       current = current->next;
    }
    current->next = malloc(sizeof(suite_t));
    current->next->name = name;
    current->next->test = test;
    current->next->n_failures = n_failures;
    current->next->n_errors = n_errors;
    current->next->next = NULL;
}

void push_test(test_t * test, char* name, char* time, enum test_status status) {
    test_t * current = test;
    while (current->next != NULL) {
        current = current->next;
    }
    current->next = malloc(sizeof(test_t));
    memset(current->next, 0, sizeof(test_t));
    current->next->name = name;
    current->next->time = time;
    current->next->status = status;
    current->next->next = NULL;
}

int main() {

    test_t * test;
    test = malloc(sizeof(test_t));
    if (test == NULL) {
        return 1;
    }
    memset(test, 0, sizeof(test_t));
    test->next = NULL;
    push_test(test, "test1", "12:45:56", STATUS_OK);
    push_test(test, "test2", "12:45:56", STATUS_SKIPPED);
    push_test(test, "test3", "12:45:56", STATUS_OK);
    push_test(test, "test3", "12:45:56", STATUS_OK);

    /* ----------------------- */

    suite_t * suite;
    suite = malloc(sizeof(suite_t));
    if (suite == NULL) {
        return 1;
    }
    memset(suite, 0, sizeof(suite_t));
    suite->next = NULL;
    push_suite(suite, "suite1", test, 10, 11);
    push_suite(suite, "suite2", test, 11, 12);
    push_suite(suite, "suite3", test, 12, 13);

    /* ----------------------- */

    report_t * report;
    report = malloc(sizeof(report_t));
    if (report == NULL) {
        return 1;
    }
    memset(report, 0, sizeof(report_t));
    report->next = NULL;
    push_report(report, FORMAT_SUBUNIT_V1, suite);

    /* ----------------------- */

    print_reports(report);
    delete_reports(report);
}
