%{
#include <stdio.h>
#include <stdlib.h>

void yyerror(char *);
int yylex(void);
%}

%token TEST SUCCESS FAILURE ERROR SKIP XFAIL UXSUCCESS
%token PROGRESS TAGS TIME DATE_VALUE TIME_VALUE NL
%token NUMBER NAME PLUS MINUS PUSH POP PART_TYPE
%token OPEN_BRACKET CLOSE_BRACKET MULTIPART_BRACKET

%%
program:
		program test_line NL
		|
		| error NL { yyerrok; }
		;

test_line:
		TEST NAME { printf("TEST\n"); }
		| status NAME details { printf("STATUS\n"); }
		| PROGRESS progress_action { printf("PROGRESS push/pop\n"); }
		| PROGRESS progress_sign NUMBER { printf("PROGRESS\n"); }
		| TAGS tags { printf("TAGS\n"); }
		| TIME DATE_VALUE TIME_VALUE { printf("TIME\n"); }
		;

details:
		|
		| bracketed
		| multipart
		;

bracketed:
		| OPEN_BRACKET lines CLOSE_BRACKET
		;

multipart:
		| MULTIPART_BRACKET lines CLOSE_BRACKET

part:
		| PART_TYPE NL NAME NL part_bytes NL
		;

part_bytes:
		| /* FIXME */
		;

lines:
		| lines NAME
		|
		;

tags:
		tags tag_sign NAME
		|
		;

status:
		SUCCESS
		| FAILURE
		| ERROR
		| SKIP
		| XFAIL
		| UXSUCCESS
		;

progress_sign:
		PLUS
		| MINUS
		|
		;

tag_sign:
		MINUS
		|
		;

progress_action:
		PUSH
		| POP
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