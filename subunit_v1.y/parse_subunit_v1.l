%{
#include <stdio.h>
#include "parse_subunit_v1.tab.h"
/* extern YYSTYPE yylval; */
int yylval;
%}

%option yylineno
%option noyywrap

%%
("test"|"testing"):?		return TEST;
("success"|"successful"):?	return SUCCESS;
"failure:"					return FAILURE;
"error:"					return ERROR;
"skip":?					return SKIP;
"xfail":?					return XFAIL;
"uxsuccess":?				return UXSUCCESS;
"progress:"					return PROGRESS;
"tags:"						return TAGS;
"time:"						return TIME;
"push"						return PUSH;
"pop"						return POP;
"-"							return MINUS;
"+"							return PLUS;
"Content-Type: type/sub-type(;parameter=value,parameter=value)" return PART_TYPE;
[0-9]+						return NUMBER;
[0-9]{4}-[0-9]{2}-[0-9]{2}  return DATE_VALUE;
[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z	return TIME_VALUE;
[a-zA-Z0-9()_/\\.-]+		return NAME;
"\[\n"						return OPEN_BRACKET;
"\]\n"						return CLOSE_BRACKET;
"[ multipart\n"				return MULTIPART_BRACKET;
"\n"						return NL;
[ \t]+			 			/* skip whitespace */
%%
