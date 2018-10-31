%{
#include <stdio.h>
#include "parse_query.tab.h"

void yyerror(char *);
extern int yylval;
%}

%%
">"			return TOK_GT;
"<"			return TOK_LT;
"="			return TOK_EQ;
"fmt"			return TOK_FMT;
"suite"			return TOK_SUITE;
"test"			return TOK_TEST;
"created"		return TOK_CREATED;
"passrate"		return TOK_PASSRATE;

"junit"|"testanything"|"subunit_v1"|"subunit_v2" return FORMAT;
[A-Z|a-z|0-9]+		return NAME;
[0-9]+              	return NUMBER;
\n                  	/* skip end line */;
[ \t]+              	/* skip whitespace */;
.           		yyerror("Unknown character");
%%

int yywrap(void) {
    return 1;
}
