
all: lex.yy.c y.tab.c y.tab.h
	gcc lex.yy.c y.tab.c -o q

lex.yy.c:
	lex parse_query.l

y.tab.c:
	yacc -d parse_query.y

clean:
	rm -f y.tab.c y.tab.h lex.yy.c
