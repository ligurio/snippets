%{
#include <stdio.h>
#include "parse_testanything.tab.h"
/* extern YYSTYPE yylval; */
int yylval;
%}

%option yylineno
%option noyywrap

%%
"ok"			return PASS;
"not"			return NE;
"Bail out!"		return BAILOUT;
[(?i:"skip")|(?i:"skipped")]	return SKIP;
"TODO"			return TODO;
"-"				return DASH;
".."			return DOTS;
"#"				return HASH;
^"..."$			return YAML_START;
^"---"$			return YAML_END;
[0-9]+			{ yylval = atoi(yytext); return NUMBER; }
[-a-zA-Z0-9\-\"\_/\.\!\*\+\<\>\}\[\]]+		return WORD;
"TAP version"	return VERSION;
"\n"			return NL;
[ \t]+			 /* skip whitespace */
%%
