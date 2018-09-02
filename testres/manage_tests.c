#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "manage_tests.h"

/*
 * Allocate a new list_t. NULL on failure.
 */

list_t *
list_new() {
  list_t *self;
  if (!(self = malloc(sizeof(list_t))))
    return NULL;
  self->head = NULL;
  self->tail = NULL;
  self->free = NULL;
  self->match = NULL;
  self->len = 0;
  return self;
}

/*
 * Free the list.
 */

void
list_destroy(list_t *self) {
  unsigned int len = self->len;
  list_node_t *next;
  list_node_t *curr = self->head;

  while (len--) {
    next = curr->next;
    if (self->free) self->free(curr->val);
    free(curr);
    curr = next;
  }

  free(self);
}

/*
 * Append the given node to the list
 * and return the node, NULL on failure.
 */

list_node_t *
list_rpush(list_t *self, list_node_t *node) {
  if (!node) return NULL;

  if (self->len) {
    node->prev = self->tail;
    node->next = NULL;
    self->tail->next = node;
    self->tail = node;
  } else {
    self->head = self->tail = node;
    node->prev = node->next = NULL;
  }

  ++self->len;
  return node;
}

/*
 * Return / detach the last node in the list, or NULL.
 */

list_node_t *
list_rpop(list_t *self) {
  if (!self->len) return NULL;

  list_node_t *node = self->tail;

  if (--self->len) {
    (self->tail = node->prev)->next = NULL;
  } else {
    self->tail = self->head = NULL;
  }

  node->next = node->prev = NULL;
  return node;
}

/*
 * Return / detach the first node in the list, or NULL.
 */

list_node_t *
list_lpop(list_t *self) {
  if (!self->len) return NULL;

  list_node_t *node = self->head;

  if (--self->len) {
    (self->head = node->next)->prev = NULL;
  } else {
    self->head = self->tail = NULL;
  }

  node->next = node->prev = NULL;
  return node;
}

/*
 * Prepend the given node to the list
 * and return the node, NULL on failure.
 */

list_node_t *
list_lpush(list_t *self, list_node_t *node) {
  if (!node) return NULL;

  if (self->len) {
    node->next = self->head;
    node->prev = NULL;
    self->head->prev = node;
    self->head = node;
  } else {
    self->head = self->tail = node;
    node->prev = node->next = NULL;
  }

  ++self->len;
  return node;
}

/*
 * Remove the given node from the list, freeing it and it's value.
 */

void
list_remove(list_t *self, list_node_t *node) {
  node->prev
    ? (node->prev->next = node->next)
    : (self->head = node->next);

  node->next
    ? (node->next->prev = node->prev)
    : (self->tail = node->prev);

  if (self->free) self->free(node->val);

  free(node);
  --self->len;
}

/*
 * Allocates a new list_node_t. NULL on failure.
 */

list_node_t *
list_node_new(void *val) {
  list_node_t *self;
  if (!(self = malloc(sizeof(list_node_t))))
    return NULL;
  self->prev = NULL;
  self->next = NULL;
  self->val = val;
  return self;
}

/*
 * Allocate a new list_iterator_t. NULL on failure.
 * Accepts a direction, which may be LIST_HEAD or LIST_TAIL.
 */

list_iterator_t *
list_iterator_new(list_t *list, list_direction_t direction) {
  list_node_t *node = direction == LIST_HEAD
    ? list->head
    : list->tail;
  return list_iterator_new_from_node(node, direction);
}

/*
 * Allocate a new list_iterator_t with the given start
 * node. NULL on failure.
 */

list_iterator_t *
list_iterator_new_from_node(list_node_t *node, list_direction_t direction) {
  list_iterator_t *self;
  if (!(self = malloc(sizeof(list_iterator_t))))
    return NULL;
  self->next = node;
  self->direction = direction;
  return self;
}

/*
 * Return the next list_node_t or NULL when no more
 * nodes remain in the list.
 */

list_node_t *
list_iterator_next(list_iterator_t *self) {
  list_node_t *curr = self->next;
  if (curr) {
    self->next = self->direction == LIST_HEAD
      ? curr->next
      : curr->prev;
  }
  return curr;
}

/*
 * Free the list iterator.
 */

void
list_iterator_destroy(list_iterator_t *self) {
  free(self);
  self = NULL;
}




/*
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
*/

/*
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
*/

/*
void push_report(report_t * reports, report_t * report) {
    report_t * current = reports;

    while (current->next != NULL) {
        current = current->next;
    }
    current->next = malloc(sizeof(report_t));
    current->next->format = report->format;
    current->next->suite = report->suite;
    current->next->next = NULL;
}
*/

/*
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
*/

/*
void push_suite(suite_t * suites, suite_t * suite) {
    suite_t * current = suites;

    while (current->next != NULL) {
       current = current->next;
    }
    current->next = malloc(sizeof(suite_t));
    current->next->name = suite->name;
    current->next->test = suite->test;
    current->next->n_failures = suite->n_failures;
    current->next->n_errors = suite->n_errors;
    current->next->next = NULL;
}
*/

/*
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
*/

/*
void push_test(test_t * tests, test_t * test) {
    test_t * current = tests;
    while (current->next != NULL) {
        current = current->next;
    }
    current->next = malloc(sizeof(test_t));
    memset(current->next, 0, sizeof(test_t));
    current->next->name = test->name;
    current->next->time = test->time;
    current->next->status = test->status;
    current->next->next = NULL;
}
*/
