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
#include <stdio.h>
#include <stdlib.h>

void yyerror(char *);
int yylex(void);
%}

%token OK NOT BAILOUT SKIP TODO
%token VERSION HASH DASH YAML PLAN
%token WORD NUMBER NL

%%
program		: program test_line NL
		| error NL { yyerrok; }
		|
		;

test_line	: VERSION NUMBER {
			printf("TAP version is %d\n", $2);
			if ($2 != 13) {
			   perror("unsupported format version\n");
			}
		}
		| PLAN comment {
			printf("PLAN\n");
			/*
			TODO:
			- first number == 1
			- second number > 1
			- if there is a plan before the test points it must be
			the first non-diagnostic line output by the test file
			- plan cannot appear in the middle of the output, nor
			can it appear more than once

			int *min = NULL, *max = NULL;
			if (sscanf(yyval, "%u..%u", min, max) != 2) {
			   perror("cannot parse plan\n");
			};
			*/
		}
		| status test_number description comment {
			printf("TESTCASE #%d\n", $2);
		}
		| comment {
			printf("COMMENT\n");
		}
		| BAILOUT string {
			printf("BAIL OUT!\n");
		}
		| YAML {
			printf("YAML\n");
		}
		;

status		: OK
		| NOT OK
		;

comment		: HASH directive string
		|
		;

test_number	: NUMBER
		|
		;

description	: string
		| DASH string
		|
		;

directive	: SKIP
		| TODO
		|
		;

string		: string WORD
		| string NUMBER
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

struct tailq_entry {
	int tc_number;
	char tc_desc;
	char tc_comment;
	TAILQ_ENTRY(tailq_entry) entries;
};

TAILQ_HEAD(, tailq_entry) report_head;

void yyerror(char *s)
{
    fprintf( stderr, "Warning: %s, line %d\n", s, yylineno);
}

int main( int argc, char **argv ) {

  progname = argv[0];

  if (argc > 1)
  {
	yyin = fopen(argv[1], "r");
	yylineno = 0;
	if (!yyin) {
		printf("Can't open file %s\n", argv[1]);
		return -1;
	}
  }

  yyparse();

/*
  struct tailq_entry *item;
  struct tailq_entry *tmp_item;
  int i;

  TAILQ_INIT(&report_head);

  for (i = 0; i < 10; i++) {
    item = malloc(sizeof(*item));
	if (item == NULL) {
	  perror("malloc failed");
	  exit(EXIT_FAILURE);
	}

    item->tc_number = i;
    TAILQ_INSERT_TAIL(&report_head, item, entries);
  }

  TAILQ_FOREACH(item, &report_head, entries) {
	printf("%d ", item->tc_number);
  }
*/

  /* close(yyin); */

  return 0;
}
