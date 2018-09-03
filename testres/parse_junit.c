/*
 * Copyright © 2018 Sergey Bronnikov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <expat.h>
#include <fcntl.h>
#include <ctype.h>

#ifndef PARSE_COMMON_H
#define PARSE_COMMON_H
#include "parse_common.h"
#endif /* PARSE_COMMON_H */

#ifdef XML_LARGE_SIZE
# if defined(XML_USE_MSC_EXTENSIONS) && _MSC_VER < 1400
#  define XML_FMT_INT_MOD "I64"
# else
#  define XML_FMT_INT_MOD "ll"
# endif
#else
# define XML_FMT_INT_MOD "l"
#endif

#ifdef XML_UNICODE_WCHAR_T
# define XML_FMT_STR "ls"
#else
# define XML_FMT_STR "s"
#endif

#define BUFFSIZE        8192

char buf[BUFFSIZE];

tailq_test *test_item;
tailq_suite *suite_item;

TAILQ_HEAD(, tailq_test) tests_head;
TAILQ_HEAD(, tailq_suite) suites_head;

const char *name_to_value(const XML_Char **attr, const char name[]) {
  char * value = NULL;
  int i;
  for (i = 0; attr[i]; i += 2) {
     const char *attr_name = attr[i];
     const char *attr_value = attr[i + 1];
     if (strcmp(attr_name, name) == 0) {
        value = attr_value;
        break;
     }
  }
  return value;
}

static void XMLCALL
start_handler(void *data, const XML_Char *elem, const XML_Char **attr)
{
  (void)data;
  char *value;

  if (strcmp(elem, "testsuite") == 0) {
     suite_item = malloc(sizeof(tailq_suite));
     if (suite_item == NULL) {
       perror("malloc failed");
     }
     memset(suite_item, 0, sizeof(tailq_suite));

     value = name_to_value(attr, "name");
     suite_item->name = malloc(sizeof(value));
     strncpy(suite_item->name, value, sizeof(value));

     /*
     value = name_to_value(attr, "hostname");
     suite_item->hostname = malloc(sizeof(value));
     strncpy(suite_item->hostname, value, sizeof(value));
     */

     suite_item->n_errors= atoi(name_to_value(attr, "errors"));
     suite_item->n_failures = atoi(name_to_value(attr, "failures"));
     //TAILQ_INSERT_TAIL(&suites_head, suite_item, entries);
  } else if (strcmp(elem, "testcase") == 0) {
     test_item = malloc(sizeof(tailq_test));
     if (test_item == NULL) {
        perror("malloc failed");
     };
     memset(test_item, 0, sizeof(tailq_test));

     /*
     value = name_to_value(attr, "name");
     test_item->name = malloc(sizeof(value));
     strncpy(test_item->name, value, sizeof(value));
     */
     
     value = name_to_value(attr, "time");
     test_item->time = malloc(sizeof(value));
     strncpy(test_item->time, value, sizeof(value));

     test_item->status = STATUS_PASS;
     TAILQ_INSERT_TAIL(&tests_head, test_item, entries);
  }  else if (strcmp(elem, "error") == 0) {
     test_item->status = STATUS_ERROR;

     /*
     value = name_to_value(attr, "comment");
     test_item->comment = malloc(sizeof(value));
     strncpy(test_item->comment, value, sizeof(value));
     */
  } else if (strcmp(elem, "failure") == 0) {
     test_item->status = STATUS_FAILURE;

     /*
     value = name_to_value(attr, "comment");
     test_item->comment = malloc(sizeof(value));
     strncpy(test_item->comment, value, sizeof(value));
     */
  }
}

static void XMLCALL
end_handler(void *data, const XML_Char *elem)
{
  (void)data;
  (void)elem;
  if (strcmp(elem, "testsuite") == 0) {
     /* TODO: check a number of failures and errors */
     printf("");
  } else if (strcmp(elem, "testcase") == 0) {
     //suite_item->tests = tests_head;
     TAILQ_INSERT_TAIL(&suites_head, suite_item, entries);
     printf("");
  }
}

void
char_handler(void *data, const char *txt, int txtlen) {
  (void)data;
  fwrite(txt, txtlen, sizeof(char), stdout);
}

tailq_suite *parse_junit(FILE *f) {
  XML_Parser p = XML_ParserCreate(NULL);
  if (! p) {
    fprintf(stderr, "Couldn't allocate memory for parser\n");
    exit(-1);
  }

  TAILQ_INIT(&tests_head);
  TAILQ_INIT(&suites_head);

  XML_UseParserAsHandlerArg(p);
  XML_SetElementHandler(p, start_handler, end_handler);
  XML_SetCharacterDataHandler(p, char_handler);

  for (;;) {
    int len, done;
    len = fread(buf, 1, BUFFSIZE, f);
    if (ferror(f)) {
       fprintf(stderr, "Read error\n");
       exit(-1);
    }
    done = feof(f);

    if (XML_Parse(p, buf, len, done) == XML_STATUS_ERROR) {
      fprintf(stderr,
              "Parse error at line %" XML_FMT_INT_MOD "u:\n%" XML_FMT_STR "\n",
              XML_GetCurrentLineNumber(p),
              XML_ErrorString(XML_GetErrorCode(p)));
      /* FIXME: free report, suite and test */
      exit(-1);
    }

    if (done) {
       break;
    }
  }
  XML_ParserFree(p);
  /*
  TAILQ_FOREACH(suite_item, &suites_head, entries) {
      //printf("suite name %s\n", suite_item->name);
      printf("suite n_failures %d\n", suite_item->n_failures);
      printf("suite n_errors %d\n", suite_item->n_errors);
  }
  */
  TAILQ_FOREACH(test_item, &tests_head, entries) {
      printf("test name %s\n", test_item->name);
      printf("test time %s\n", test_item->time);
      printf("test status %d\n", test_item->status);
  }

  return NULL;
}
