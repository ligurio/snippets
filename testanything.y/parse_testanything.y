%{
#include <stdio.h>
#include <stdlib.h>

void yyerror(char *);
int yylex(void);
%}

%token OK NOT BAILOUT SKIP SKIPPED TODO
%token HASH DASH DOTS YAML_START YAML_END
%token VERSION WORD NUMBER NL 

%%
program:
		program test_line NL
		|
		| error NL { yyerrok; }
		;

test_line:
		VERSION NUMBER { printf("TAP version is %d\n", $2); }
		| plan directive { printf("PLAN\n"); }
		| status test_number desc directive { printf("TESTCASE #%d\n", $2); }
		| comment { printf("COMMENT\n"); }
		| BAILOUT string { printf("BAIL OUT!\n"); }
		| YAML_START string YAML_END { /* ignore */ }
		;

status:
		OK
		| NOT OK
		;

comment: /* empty */
		HASH
		| HASH string
		;

test_number: /* empty */
		| NUMBER
		;

/*
Example:

1..10
1..0 # Skipped: WWW::Mechanize not installed

- is optional
- if there is a plan before the test points it must be the first non-diagnostic
line output by the test file
- plan cannot appear in the middle of the output, nor can it appear more than once
*/

plan:	/* empty */
		| NUMBER DOTS NUMBER { printf("Max number of tests is %d\n", $3); }
		; 

/*

Example:

ok 42 this is the description of the test

Any text after the test number but before a # is the description of
the test point.

Descriptions should not begin with a digit so that they are not confused with
the test point number. The harness may do whatever it wants with the
description.

The test point may include a directive, following a hash on the test
line. There are currently two directives allowed: TODO and SKIP.

*/

desc:	/* empty */
		| string
		| DASH string
		;

directive:	/* empty */
		| HASH SKIP string
		| HASH SKIPPED string
		| HASH TODO string
		;

string: /* empty */
		string WORD
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

  close(yyin);
  return 0;
}
