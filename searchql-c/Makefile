PROGRAM	= parse_query

OBJS	= $(PROGRAM).tab.o $(PROGRAM).o
SRCS	= $(PROGRAM).tab.c $(PROGRAM).c
CC	= gcc
CFLAGS	= -O3

REGRESS	= t1 t2 t3 t4 t5

all: $(PROGRAM)

$(OBJS): $(SRCS)
	$(CC) $(CFLAGS) -c $*.c -o $@ -O

$(PROGRAM).tab.c: $(PROGRAM).y
	yacc -b $(PROGRAM) -d $(PROGRAM).y

$(PROGRAM).c: $(PROGRAM).l
	lex -o$@ $<

$(PROGRAM): $(OBJS)
	$(CC) $(OBJS) -o $@

regress: all
	@for t in $(REGRESS); do echo "==== t/$$t"; ./${PROGRAM} t/$$t || (echo "--"; cat t/$$t); done

clean:
	rm -f $(OBJS) $(PROGRAM) $(PROGRAM).c $(PROGRAM).tab.c $(PROGRAM).tab.h core

.PHONY:	regress clean
