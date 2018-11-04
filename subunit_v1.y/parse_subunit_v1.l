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
[0-9]+						return NUMBER;
[0-9]{4}-[0-9]{2}-[0-9]{2}  return DATE_VALUE;
[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z	return TIME_VALUE;
[a-zA-Z0-9()_/\\.-]+		return NAME;
"\n"						return NL;
[ \t]+			 			/* skip whitespace */
%%

/*
test|testing|test:|testing: test LABEL
success|success:|successful|successful: test LABEL
success|success:|successful|successful: test LABEL DETAILS
failure: test LABEL
failure: test LABEL DETAILS
error: test LABEL
error: test LABEL DETAILS
skip[:] test LABEL
skip[:] test LABEL DETAILS
xfail[:] test LABEL
xfail[:] test LABEL DETAILS
uxsuccess[:] test LABEL
uxsuccess[:] test LABEL DETAILS
progress: [+|-]X
progress: push
progress: pop
tags: [-]TAG ...
time: YYYY-MM-DD HH:MM:SSZ

LABEL: UTF8*
NAME: UTF8*
DETAILS ::= BRACKETED | MULTIPART
BRACKETED ::= '[' CR UTF8-lines ']' CR
MULTIPART ::= '[ multipart' CR PART* ']' CR
PART ::= PART_TYPE CR NAME CR PART_BYTES CR
PART_TYPE ::= Content-Type: type/sub-type(;parameter=value,parameter=value)
PART_BYTES ::= (DIGITS CR LF BYTE{DIGITS})* '0' CR LF

*/
