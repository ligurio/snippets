%{
#include <stdio.h>
#include "parse_testanything.tab.h"
/* extern YYSTYPE yylval; */
int yylval;
%}

%option yylineno
%option noyywrap

%%
"ok"				return OK;
"not"				return NOT;
"Bail out!"			return BAILOUT;
"TODO"				return TODO;
"TAP version"			return VERSION;
[Ss][Kk][Ii][Pp]		return SKIP;
[Ss][Kk][Ii][Pp][Pp][Ee][Dd]	return SKIPPED;
-				return DASH;
#				return HASH;
\.{2}				return DOTS;
^\.{3}$				return YAML_START;
^-{3}$				return YAML_END;
[0-9]+				{ yylval = atoi(yytext); return NUMBER; }
[-a-zA-Z0-9:$^"',_\./\!*+<>}\[\]]+	return WORD;
\n				return NL;
[ \t]+			 	/* skip whitespace */
%%
