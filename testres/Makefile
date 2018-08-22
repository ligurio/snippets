CFLAGS		= -O3 -std=c99
SRCS		= testres.c parse_junit.c parse_testanything.c
BIN		= testres.cgi

CGIDIR		= /var/www/cgi-bin

all: testres.cgi

testres.cgi: $(SRCS)
	$(CC) -static -L/usr/local/lib $(SRCS) -o $(BIN) -lexpat -lz

install: all
	mkdir -p $(CGIDIR)
	install -m 0755 testres.cgi $(CGIDIR)

test:
	make -C tests

clean:
	rm -f $(BIN)

check:
	cppcheck --template "{file} ({line}): {severity} ({id}): {message}" \
		--enable=warning,portability,performance \
		--suppress=redundantAssignment \
		--suppress=uselessAssignmentPtrArg \
		--suppress=incorrectStringBooleanError \
		--std=c89 *.c *.h 2> cppcheck.log

.PHONY: install
