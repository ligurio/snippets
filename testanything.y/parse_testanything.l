/*
 * Written by Sergey Bronnikov <estetus@gmail.com>.
 * Public domain.
 */

%{
#include <stdio.h>
#include "parse_testanything.tab.h"
extern YYSTYPE yylval;
%}

%option yylineno
%option noyywrap
 
%%
"#"				return COMMENT;
"not ok"			return TC_FAIL;
"ok"				return TC_PASS;
"Bail out!"			return TC_BAIL;
"SKIP"				return TC_SKIP;
"TODO"				return TC_TODO;
"-"				return DASH;
"..."				return YAML_START;
"---"				return YAML_END;
[a-zA-Z';,.!@#$%^&*()_+{}\/-]+	return STRING;
[0-9]+				{ yylval = atoi(yytext); return NUMBER; }
[0-9]+..[0-9]+			return PLAN;
"TAP version"			return VERSION;
"\n"				return EOLN;
[ \t]				;
%%
