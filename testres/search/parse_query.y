%{
    #include <stdio.h>
    void yyerror(char *);
    int yylex(void);

    int sym[26];
%}

%token TOK_BINARY_OP TOK_DELIM TOK_QUOTE
%token TOK_GT TOK_LT TOK_EQ
%token TOK_FMT TOK_SUITE TOK_TEST TOK_CREATED TOK_PASSRATE
%token FORMAT NAME NUMBER

%left '+' '-'
%left '*' '/'

%%

query:
        query expression
        | /* NULL */
        ;

expression:
		TOK_TEST TOK_DELIM NAME		   {  }
        | TOK_SUITE TOK_DELIM NAME     {  }
        | TOK_FMT TOK_DELIM FORMAT     {  }
        | '(' expression ')'           {  }
        ;
%%

void yyerror(char *s) {
    fprintf(stderr, "%s\n", s);
}

int main(void) {
    yyparse();
}
