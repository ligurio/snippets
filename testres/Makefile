CC        ?= gcc
CFLAGS	  += -O1 -g3
CFLAGS	  += -Wall -Wextra -Wfloat-equal -Wundef
CFLAGS	  += -Wpointer-arith -Wcast-align -Wshadow
CFLAGS	  += -Wstrict-overflow=5 -Wwrite-strings -Waggregate-return
CFLAGS	  += -Wswitch-enum -Wunreachable-code -Winit-self
LDFLAGS   += -lexpat

SRCS	= testres.c manage_tests.c parse_common.c \
	parse_junit.c parse_subunit_v2.c parse_testanything.c \
	ui_common.c
OBJ 	= testres.o manage_tests.o parse_common.o \
	parse_junit.o parse_subunit_v2.o parse_testanything.o \
	ui_common.o
PLIST	= testres.plist manage_tests.plist parse_common.plist \
	parse_junit.plist parse_subunit_v2.plist parse_testanything.plist \
	ui_common.plist
BIN	= testres.cgi
CGIDIR	= /var/www/cgi-bin

all: $(BIN)

$(BIN): $(OBJ) $(SRCS)
	$(CC) -L/usr/local/lib $(SRCS) -o $(BIN) $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

%.plist: %.c
	@clang --analyze $<
	echo $<

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
	rm -f $(BIN) $(OBJ) $(PLIST) cppcheck.log *.core tags

techdebt:
	@find . -name '*.[ch]' | xargs grep -E " TODO|FIXME"

check: $(PLIST)
	@cppcheck --template "{file} ({line}): {severity} ({id}): {message}" \
		--enable=warning,portability,performance \
		--suppress=redundantAssignment \
		--suppress=uselessAssignmentPtrArg \
		--suppress=incorrectStringBooleanError \
		--std=c89 *.c *.h 2> cppcheck.log

.PHONY: clean check install tags test techdebt
