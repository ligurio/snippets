PARSE = parse_query

all: ${PARSE}.tab.c ${PARSE}.tab.h lex.${PARSE}.c
	gcc ${PARSE}.tab.c lex.${PARSE}.c -o q -lfl 

lex.${PARSE}.c:
	lex -P${PARSE} ${PARSE}.l

${PARSE}.tab.c:
	yacc -b ${PARSE} -d ${PARSE}.y

clean:
	rm -f ${PARSE}.tab.c ${PARSE}.tab.h lex.${PARSE}.c
