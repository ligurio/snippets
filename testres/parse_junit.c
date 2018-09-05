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
#include <fcntl.h>
#include <ctype.h>
#include <expat.h>

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

/* https://github.com/kristapsdz/divecmd/blob/master/parser.c */

char buf[BUFFSIZE];

tailq_test testq;
tailq_suite suiteq;

tailq_test *test_item;
tailq_suite *suite_item;

const XML_Char *name_to_value(const XML_Char **attr, const char name[]) {
  const XML_Char *value = NULL;
  int i;
  for (i = 0; attr[i]; i += 2) {
     if (strcmp(attr[i], name) == 0) {
        value = malloc(sizeof(attr[i + 1]));
        strncpy(value, attr[i + 1], sizeof(attr[i + 1]));
        break;
     }
  }
  return value;
}

static void XMLCALL
start_handler(void *data, const XML_Char *elem, const XML_Char **attr)
{
  (void)data;
  const char *value;

  if (strcmp(elem, "testsuite") == 0) {
     suite_item = malloc(sizeof(tailq_suite));
     if (suite_item == NULL) {
       perror("malloc failed");
     }
     memset(suite_item, 0, sizeof(tailq_suite));
     suite_item->name = name_to_value(attr, "name");
     suite_item->hostname = name_to_value(attr, "hostname");
     suite_item->n_errors = atoi(name_to_value(attr, "errors"));
     suite_item->n_failures = atoi(name_to_value(attr, "failures"));
  } else if (strcmp(elem, "testcase") == 0) {
     test_item = malloc(sizeof(tailq_test));
     if (test_item == NULL) {
        perror("malloc failed");
     };
     memset(test_item, 0, sizeof(tailq_test));
     test_item->name = name_to_value(attr, "name");
     test_item->time = name_to_value(attr, "time");
     test_item->status = STATUS_PASS;
  }  else if (strcmp(elem, "error") == 0) {
     test_item->status = STATUS_ERROR;
     test_item->comment = name_to_value(attr, "comment");
  } else if (strcmp(elem, "failure") == 0) {
     test_item->status = STATUS_FAILURE;
     test_item->comment = name_to_value(attr, "comment");
  }
}

static void XMLCALL
end_handler(void *data, const XML_Char *elem)
{
  (void)data;
  (void)elem;
  if (strcmp(elem, "testsuite") == 0) {
     /* TODO: check a number of failures and errors */
     /* FIXME: suite_item->testq = test_item->head; */
     TAILQ_INSERT_TAIL(&suiteq.head, suite_item, entries);
  } else if (strcmp(elem, "testcase") == 0) {
     TAILQ_INSERT_TAIL(&testq.head, test_item, entries);
  }
}

void
char_handler(void *data, const char *txt, int txtlen) {
  (void)data;
  /* TODO: fwrite(txt, txtlen, sizeof(char), stdout); */
}

tailq_suite *parse_junit(FILE *f) {
  XML_Parser p = XML_ParserCreate(NULL);
  if (! p) {
    fprintf(stderr, "Couldn't allocate memory for parser\n");
    exit(-1);
  }

  TAILQ_INIT(&testq.head);
  TAILQ_INIT(&suiteq.head);

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
      /* FIXME: free tailq_suite, tailq_test */
      exit(-1);
    }
    if (done) {
       break;
    }
  }
  XML_ParserFree(p);

  print_suites(&suiteq);
  print_tests(&testq);

  return NULL;
}
