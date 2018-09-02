#include <stdlib.h>

#ifndef PARSE_COMMON_H
#define PARSE_COMMON_H
#include "parse_common.h"
#endif /* PARSE_COMMON_H */

//
// Copyright (c) 2010 TJ Holowaychuk <tj@vision-media.ca>
//

#define LIST_VERSION "0.0.5"

/*
 * list_t iterator direction.
 */

typedef enum {
    LIST_HEAD
  , LIST_TAIL
} list_direction_t;

/*
 * list_t node struct.
 */

typedef struct list_node {
  struct list_node *prev;
  struct list_node *next;
  void *val;
} list_node_t;

/*
 * list_t struct.
 */

typedef struct {
  list_node_t *head;
  list_node_t *tail;
  unsigned int len;
  void (*free)(void *val);
  int (*match)(void *a, void *b);
} list_t;

/*
 * list_t iterator struct.
 */

typedef struct {
  list_node_t *next;
  list_direction_t direction;
} list_iterator_t;

// Node prototypes.

list_node_t *
list_node_new(void *val);

// list_t prototypes.

list_t *
list_new();

list_node_t *
list_rpush(list_t *self, list_node_t *node);

list_node_t *
list_lpush(list_t *self, list_node_t *node);

list_node_t *
list_rpop(list_t *self);

list_node_t *
list_lpop(list_t *self);

list_node_t *
list_print(list_t *self);

void
list_remove(list_t *self, list_node_t *node);

void
list_destroy(list_t *self);

// list_t iterator prototypes.

list_iterator_t *
list_iterator_new(list_t *list, list_direction_t direction);

list_iterator_t *
list_iterator_new_from_node(list_node_t *node, list_direction_t direction);

list_node_t *
list_iterator_next(list_iterator_t *self);

void
list_iterator_destroy(list_iterator_t *self);
