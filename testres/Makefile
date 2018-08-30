CFLAGS	+= -Wall -Wextra -Wfloat-equal -Wundef
CFLAGS	+= -Wpointer-arith -Wcast-align -Wshadow
CFLAGS	+= -Wstrict-overflow=5 -Wwrite-strings -Waggregate-return
CFLAGS	+= -Wswitch-enum -Wunreachable-code -Winit-self
CFLAGS	+= -O1 -g -fPIC -fsigned-char
# TODO: -Wstrict-prototypes -Wconversion -Wcast-qual -Werror

SRCS	= testres.c manage_tests.c parse_common.c \
	parse_junit.c parse_subunit_v2.c parse_testanything.c \
	ui_common.c
OBJ 	= testres.o manage_tests.o parse_common.o \
	parse_junit.o parse_subunit_v2.o parse_testanything.o \
	ui_common.o
BIN	= testres.cgi
CGIDIR	= /var/www/cgi-bin

all: $(BIN)

$(BIN): $(OBJ) $(SRCS)
	$(CC) -L/usr/local/lib $(SRCS) -o $(BIN) -lexpat

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

install: all
	@mkdir -p $(CGIDIR)
	@install -m 0755 $(BIN) $(CGIDIR)

uninstall:
	@rm -f $(CGIDIR)/$(BIN)

test:
	@make -C tests

tags:
	@find . -name '*.[ch]' | xargs ctags

clean:
	@make -C tests clean
	rm -f $(BIN) $(OBJ) cppcheck.log *.core

check:
	cppcheck --template "{file} ({line}): {severity} ({id}): {message}" \
		--enable=warning,portability,performance \
		--suppress=redundantAssignment \
		--suppress=uselessAssignmentPtrArg \
		--suppress=incorrectStringBooleanError \
		--std=c89 *.c *.h 2> cppcheck.log

.PHONY: install clean check test tags
