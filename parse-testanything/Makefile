YFLAGS        = -d
PROGRAM       = tossil
OBJS          = y.tab.o lex.yy.o
SRCS          = y.tab.c lex.yy.c
CC            = gcc
CCFLAGS		  = -ggdb

REGRESS		  = t1 t2 t3 t4 t5 t6 t7

all:            $(PROGRAM)

${OBJS}:    	$(SRCS)
				$(CC) $(CCFLAGS) -c $*.c -o $@ -O

y.tab.c:		parse.y
				yacc $(YFLAGS) parse.y

lex.yy.c:		parse.l
				lex parse.l

tossil:			$(OBJS)
				$(CC) $(CCFLAGS) $(OBJS)  -o $@

regress:		all
				@for t in $(REGRESS); do echo "==== t/$$t"; ./${PROGRAM} t/$$t; done

clean:			
				rm -f $(OBJS) core *~ \#* *.o $(PROGRAM) \
				y.* lex.yy.* parse.tab.*

.PHONY:			regress
