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

%{
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "parse_common.h"

void yyerror(char *);
int yylex(void);
void set_missed_status(long tc_missed);
tailq_test *create_new_test(void);
void print_tests(struct testq * tests);

enum parse_error {
	ERR_UNSUPPORTED_VERSION,
	ERR_WRONG_PLAN,
	ERR_MALLOC
};

tailq_suite *suite_item = NULL;
struct suiteq *suites = NULL;
static char bailout = 0;	/* bail out flag */
static char todo = 0;		/* todo flag */
static char skip = 0;		/* skip flag */
static long plan = 0;		/* number of planned testcases */
static long tc_num = 0;		/* number of testcases in a suite */
enum parse_error error;

void
print_suites(struct suiteq * suites)
{
	tailq_suite *suite_item = NULL;
	TAILQ_FOREACH(suite_item, suites, entries) {
		const char *name = "noname";
		if (suite_item->name != (char *)NULL) {
			name = suite_item->name;
		}
		printf("\nSUITE: %s", name);
		if (suite_item->timestamp != (char *)NULL) {
			printf(" (%s)", suite_item->timestamp);
		}
		printf("\n");
		if (!TAILQ_EMPTY(suite_item->tests)) {
			print_tests(suite_item->tests);
		} else {
			printf("None tests.\n");
		}
	}
}

void
print_tests(struct testq * tests)
{
	tailq_test *test_item = NULL;
	TAILQ_FOREACH(test_item, tests, entries) {
	   printf("%s\n", test_item->name);
	}
}

tailq_test *create_new_test(void) {

   tailq_test *test_item = NULL;
   test_item = calloc(1, sizeof(tailq_test));
   if (test_item == NULL) {
      fprintf(stderr, "malloc failed %s, %d", __FILE__, __LINE__);
   }

   return test_item;
}

/*
* calculate number of tests missed in a report
* due to bail out and add them to a suite
*/
void set_missed_status(long tc_missed) {
   long i = 0;
   for(i = 0; i++; i <= tc_missed) {
      tailq_test *test = create_new_test();
      test->name = NULL;
      test->status = STATUS_SKIP;
      TAILQ_INSERT_TAIL(suite_item->tests, test, entries);
   }
}

%}

%token NOT OK BAILOUT SKIP TODO
%token HASH DASH PLAN TAP_VERSION
%token WORD NUMBER NL YAML_START YAML_END

%union {
	long long_val;
	char *string;
};

%type <long_val>	NUMBER
%type <long_val>	test_number
%type <string> 		WORD
%type <string> 		PLAN
%type <string> 		status

%%
program		: program test_line
		| error NL { yyerrok; }
		|
		;

test_line	: TAP_VERSION NUMBER NL {
			int version = $2;
			fprintf(stderr, "TAP version is %d\n", version);
			assert(version == 13);
		}
		| PLAN comment NL {
			long min = 0, max = 0;
			if (sscanf($1, "%lu..%lu", &min, &max) != 2) {
			   error = ERR_WRONG_PLAN;
			   fprintf(stderr, "cannot parse plan\n");
			   /* FIXME: handle exit */
			}

			fprintf(stderr, "PLAN: %lu --> %lu\n", min, max);
			if ((min != 1) || (max < 0)) {
			   error = ERR_WRONG_PLAN;
			   /* FIXME: handle exit */
			}
			/* assert((tc_num == 0) && (plan > 0)); */

			if (max == 0) {
			   fprintf(stderr, "bailout=%d, todo=%d, skip=%d\n", bailout, todo, skip);
			   if ((bailout == 1) || (todo == 1) || (skip == 1)) {
			      if ((max - min) > 0) {
			         set_missed_status(max - tc_num);
			      }
			      /* FIXME: handle exit */
			   }
			} else {
			   if (plan == 0) {
			      if (tc_num == 0) {
			         fprintf(stderr, "suite start\n");
			         plan = max;
			      } else {
			         fprintf(stderr, "suite end\n");
			         /* assert(tc_num == number of tests) */
			      }
			   } else {
			      fprintf(stderr, "suite end and start a new suite\n");
			      /* suite end, use plan */
			      /* init suites, save a suite and set to zero */
			      /* assert(tc_num == plan == number of tests) */
			   }
			}
		}
		| status test_number description comment NL {
			/* char *status = $1; */
			long test_number = $2;
			/* char *desc = $3; */
			/* char *comment = $4; */

			fprintf(stderr, " TESTCASE\n");
			if (suite_item == NULL) {
			   suite_item = calloc(1, sizeof(tailq_suite));
			   if (suite_item == NULL) {
			      error = ERR_MALLOC;
			      fprintf(stderr, "malloc failed");
			      /* FIXME: handle exit */
			   }
			   suite_item->tests = calloc(1, sizeof(struct testq));
			   if (suite_item->tests == NULL) {
			      error = ERR_MALLOC;
			      fprintf(stderr, "malloc failed");
			      free(suite_item);
			      /* FIXME: handle exit */
			   }
			   TAILQ_INIT(suite_item->tests);
			}

			tc_num++;
			/*
			if (test_number != 0) {
			   printf("tc number %d\n", test_number);
			   assert(test_number == tc_num);
			}
			*/
			tailq_test *test_item = create_new_test();
			if (test_item == NULL) {
			   error = ERR_MALLOC;
			   free(suite_item);
			   /* FIXME: handle exit */
			}
			/* test_item->name = calloc(1, sizeof(desc) + 1);
			strcpy(test_item->name, desc); */
			/* test_item->status = ; */
			TAILQ_INSERT_TAIL(suite_item->tests, test_item, entries);
			test_item = NULL;
		}
		| comment NL {
			fprintf(stderr, "COMMENT\n");
		}
		| BAILOUT string NL {
			fprintf(stderr, "BAIL OUT! Set status in missed tests\n");
			set_missed_status(plan - tc_num);
		}
		| YAML_START NL yaml_strings YAML_END NL {
			fprintf(stderr, "YAML\n");
		}
		;

comment		: HASH directive string
		|
		;

test_number	: NUMBER
		| { }
		;

description	: string
		| DASH string
		|
		;

status		: OK { fprintf(stderr, "PASSED"); }
		| NOT OK { fprintf(stderr, "FAILED"); }
		;

directive	: TODO { fprintf(stderr, " TODO "); todo = 1; }
		| SKIP { fprintf(stderr, " SKIP "); skip = 1; }
		|
		;

string		: string WORD
		| string NUMBER
		|
		;

yaml_strings: yaml_strings string NL
		|
		;
%%

#include <ctype.h>
#include <sys/queue.h>

char *progname;
extern int yylex();
extern int yyparse();
extern int yylineno;
extern FILE *yyin;

void yyerror(char *s)
{
    fprintf(stderr, "Warning: %s, line %d\n", s, yylineno);
}

int main( int argc, char **argv ) {

  progname = argv[0];

  if (argc > 1)
  {
	yyin = fopen(argv[1], "r");
	yylineno = 0;
	if (!yyin) {
		fprintf(stderr, "Can't open file %s\n", argv[1]);
		return -1;
	}
  }

  yyparse();
  /* print_suites(suites); */

  return 0;
}
