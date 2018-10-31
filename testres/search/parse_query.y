%{
    #include <stdio.h>
    void yyerror(char *);
    int yylex(void);
%}

%token TOK_GT TOK_LT TOK_EQ
%token TOK_FMT TOK_SUITE TOK_TEST TOK_CREATED TOK_PASSRATE
%token FORMAT NAME NUMBER

%%

query:
        query expression
        | /* NULL */
        ;

expression:
	TOK_TEST TOK_EQ NAME	{ printf("TOK_TEST\n"); }
        | TOK_SUITE TOK_EQ NAME	{ printf("TOK_SUITE\n"); }
        | TOK_FMT TOK_EQ FORMAT	{ printf("TOK_FMT\n"); }
        ;
%%

void yyerror(char *s) {
    fprintf(stderr, "%s\n", s);
}

int main(void) {
    yyparse();
}
