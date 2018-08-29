CFLAGS	= -O1 -Wall
SRCS	= testres.c parse_junit.c parse_subunit_v2.c parse_testanything.c parse_common.c manage_tests.c
OBJ 	= testres.o parse_junit.o parse_subunit_v2.o parse_testanything.o parse_common.o manage_tests.o
BIN	= testres.cgi
CGIDIR	= /var/www/cgi-bin


all: testres.cgi

testres.cgi: $(OBJ) $(SRCS)
	$(CC) -L/usr/local/lib $(SRCS) -o $(BIN) -lexpat

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

install: all
	@mkdir -p $(CGIDIR)
	@install -m 0755 testres.cgi $(CGIDIR)

uninstall:
	@rm -f $(CGIDIR)/testres.cgi

test:
	@make -C tests

tags:
	@find . -name '*.[ch]' | xargs ctags

clean:
	rm -f $(BIN) $(OBJ) cppcheck.log *.core
	@make -C tests clean

check:
	cppcheck --template "{file} ({line}): {severity} ({id}): {message}" \
		--enable=warning,portability,performance \
		--suppress=redundantAssignment \
		--suppress=uselessAssignmentPtrArg \
		--suppress=incorrectStringBooleanError \
		--std=c89 *.c *.h 2> cppcheck.log

.PHONY: install clean check test tags
