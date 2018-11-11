%{
#include <stdio.h>
#include "parse_testanything.tab.h"
int yylval;
%}

%option yylineno
%option noyywrap

DIGITS		[0-9]+

%%
ok				return OK;
not				return NOT;
"Bail out!"			return BAILOUT;
"TODO"				return TODO;
^"TAP version"			return VERSION;
[Ss][Kk][Ii][Pp]		return SKIP;
[Ss][Kk][Ii][Pp][Pp][Ee][Dd]	return SKIPPED;
-				return DASH;
#				return HASH;
1..[0-9]+				return PLAN;
^\.{3}$(.|\n)*^-{3}$	return YAML;
{DIGITS}+			{ yylval = atoi(yytext); return NUMBER; }
[-a-zA-Z0-9:$^"',_\./\!*+<>}\[\]]+	return WORD;
\n				return NL;
[ \t]+			 	/* skip whitespace */
%%
