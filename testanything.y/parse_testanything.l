/*
 * Copyright © 2018 Sergey Bronnikov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

%{
#include <stdio.h>
#include "parse_testanything.tab.h"
int yylval;
%}

%option yylineno
%option noyywrap

DIGITS		[0-9]+
YAML_START	"---\n"
YAML_END	"..."|"---"
DOTS		".."
SKIP		[Ss][Kk][Ii][Pp]([Pp][Ee][Dd])?

%%
ok				return OK;
not				return NOT;
"Bail out!"			return BAILOUT;
"TODO"				return TODO;
^"TAP version"			return VERSION;
{SKIP}{1}			return SKIP;
-				return DASH;
#				return HASH;
1{DOTS}{1}[0-9]+		return PLAN;
{YAML_START}{1}(.|\n)*{YAML_END}{1}	return YAML;
{DIGITS}+			{ yylval = atoi(yytext); return NUMBER; }
[[:alnum:][:punct:]]+		return WORD;
\n				return NL;
[ \t]+			 	/* skip whitespace */
%%
