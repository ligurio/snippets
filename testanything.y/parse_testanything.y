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

void yyerror(char *);
int yylex(void);
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
%type <string> 		string
%type <string> 		description

%%
program		: program test_line
		| error NL { yyerrok; }
		|
		;

test_line	: TAP_VERSION NUMBER NL {
			printf("TAP version is %d\n", $2);
			if ($2 != 13) {
			   perror("Unsupported format version\n");
			}
		}
		| PLAN comment NL {
			printf("PLAN");
			/*
			TODO:
			- if there is a plan before the test points it must be
			the first non-diagnostic line output by the test file
			- plan cannot appear in the middle of the output, nor
			can it appear more than once
			*/

			long min = 0, max = 0;
			if (sscanf($1, "%d..%d", &min, &max) != 2) {
				perror("Cannot parse plan\n");
			} else {
				printf(" %d -- %d\n", min, max);
				assert(min == 1);
				assert(max >= 0);
			};
		}
		| status test_number description comment NL {
			if ($2 != 0) {
				printf(" TESTCASE #%d\n", $2);
			} else {
				printf(" TESTCASE\n");
			}
		}
		| comment NL {
			printf("COMMENT\n");
		}
		| BAILOUT string NL {
			printf("BAIL OUT!\n");
		}
		| YAML_START NL yaml_strings YAML_END NL {
			printf("YAML\n");
		}
		;

comment		: HASH directive string {
				if ($3 != NULL) { printf(" %s ", $3); }
			}
		|
		;

test_number	: NUMBER
		|
		;

description	: string
		| DASH string
		|
		;

status	: OK { printf("PASSED"); }
		| NOT OK { printf("FAILED"); }
		;

directive	: TODO { printf(" TODO "); }
		| SKIP { printf(" SKIP "); }
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

  return 0;
}
