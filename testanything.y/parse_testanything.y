/*
 * Written by Sergey Bronnikov <estetus@gmail.com>.
 * Public domain.
 */

%{
#include <stdio.h>
#include <stdlib.h>

void yyerror(char *);
int yylex(void);
%}

%debug
%token TC_FAIL TC_PASS TC_BAIL TC_SKIP TC_TODO STRING NUMBER VERSION EOLN 
%token COMMENT DASH PLAN YAML_START YAML_END

%%
line:	/* empty */
		| line expr
		| line expr EOLN
		| line EOLN

strings: /* empty */
		| STRING
		| strings NUMBER
		| strings STRING
		;

YAML:	/* empty */
		| YAML_START EOLN YAML_END EOLN
		;

TC_STATUS: TC_PASS { }
		| TC_FAIL { }	
		| TC_BAIL { }
		;

expr:	error { yyclearin; yyerrok; }
		| TC_STATUS strings YAML { printf("Testcase\n"); }
		| TC_STATUS DASH strings YAML { printf("Testcase\n"); }
		| TC_STATUS NUMBER strings YAML { printf("Testcase %d\n", $2); }
		| TC_STATUS NUMBER DASH strings YAML { printf("Testcase %d. Comment \n", $2); }
		| TC_STATUS NUMBER DASH COMMENT TC_SKIP strings YAML { printf("Testcase SKIP. Comment\n"); }
		| TC_STATUS NUMBER DASH strings COMMENT TC_SKIP strings YAML { printf("Testcase TODO. Comment\n"); }
		| TC_STATUS NUMBER DASH COMMENT TC_TODO strings YAML { printf("Testcase TODO. Comment\n"); }
		| TC_STATUS NUMBER DASH strings COMMENT TC_TODO strings YAML { printf("Testcase TODO. Comment\n"); }
		| PLAN { printf("Plan \n"); }
		| PLAN COMMENT strings { printf("Plan \n"); }
		| VERSION NUMBER { printf("Version is %d\n", $2); }
		| COMMENT strings { printf("Comment \n"); }
		;
%%

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/queue.h>

char *progname;
extern int yylex();
extern int yyparse();
extern int yylineno;
extern FILE *yyin;
FILE *in;

enum tc_status { PASS, FAIL, BAIL };

struct tailq_entry {
	int tc_number;
	char tc_desc;
	char tc_comment;
	TAILQ_ENTRY(tailq_entry) entries;
};

TAILQ_HEAD(, tailq_entry) report_head;

void yyerror( char *s )
{
#ifdef DEBUG
  fprintf( stderr, "Oops: %s in line %d\n", s, yylineno);
  exit(-1);
#endif
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
  printf("\n");

  return 0;
}
