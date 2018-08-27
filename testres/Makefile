CFLAGS	= -O3 -std=c99 -Wall
SRCS	= testres.c parse_junit.c parse_testanything.c parse.c
BIN	= testres.cgi
CGIDIR		= /var/www/cgi-bin

all: testres.cgi

testres.cgi: $(SRCS)
	$(CC) -static -L/usr/local/lib $(SRCS) -o $(BIN) -lexpat

install: all
	@mkdir -p $(CGIDIR)
	@install -m 0755 testres.cgi $(CGIDIR)

test:
	@make -C tests

tags:
	@find . -name '*.[ch]' | xargs ctags

clean:
	rm -f $(BIN) cppcheck.log

check:
	cppcheck --template "{file} ({line}): {severity} ({id}): {message}" \
		--enable=warning,portability,performance \
		--suppress=redundantAssignment \
		--suppress=uselessAssignmentPtrArg \
		--suppress=incorrectStringBooleanError \
		--std=c89 *.c *.h 2> cppcheck.log

.PHONY: install clean check test tags
