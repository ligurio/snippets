PREFIX	  ?= /usr/local

CC        ?= gcc
CFLAGS	  += -O1 -g3
CFLAGS	  += -Wall -Wextra -Wfloat-equal -Wundef
CFLAGS	  += -Wpointer-arith -Wcast-align -Wshadow
CFLAGS	  += -Wstrict-overflow=5 -Wwrite-strings -Waggregate-return
CFLAGS	  += -Wswitch-enum -Wunreachable-code -Winit-self
LDFLAGS   += -lexpat

SRCS	= testres.c parse_common.c \
	parse_junit.c parse_subunit_v2.c parse_testanything.c \
	ui_common.c
OBJ 	= testres.o parse_common.o \
	parse_junit.o parse_subunit_v2.o parse_testanything.o \
	ui_common.o
PLIST	= testres.plist parse_common.plist \
	parse_junit.plist parse_subunit_v2.plist parse_testanything.plist \
	ui_common.plist
BIN	= testres
CGIBIN	= $(BIN)-static
CGIDIR	= /var/www/cgi-bin

all: $(BIN) $(CGIBIN)

$(BIN): $(OBJ) $(SRCS)
	$(CC) -L/usr/local/lib $(SRCS) -o $(BIN) $(LDFLAGS)

$(CGIBIN): $(OBJ) $(SRCS)
	$(CC) -static -L/usr/local/lib $(SRCS) -o $(CGIBIN) $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

%.plist: %.c
	@clang --analyze $<

install: all
	@mkdir -p $(CGIDIR)
	@install -m 0755 $(CGIBIN) $(CGIDIR)
	@install -m 0755 $(BIN) $(PREFIX)/bin

uninstall:
	@rm -f $(CGIDIR)/$(CGIBIN)
	@rm -f $(PREFIX)/bin/$(BIN)

test:
	@make -C tests

tags:
	@find . -name '*.[ch]' | xargs ctags

clean:
	@make -C tests clean
	rm -f $(BIN) $(CGIBIN) $(OBJ) $(PLIST) cppcheck.log *.core tags

techdebt:
	@find . -name '*.[ch]' | xargs grep -E " TODO|FIXME"

check: $(PLIST)
	@cppcheck --template "{file} ({line}): {severity} ({id}): {message}" \
		--enable=warning,portability,performance \
		--suppress=redundantAssignment \
		--suppress=uselessAssignmentPtrArg \
		--suppress=incorrectStringBooleanError \
		--std=c89 *.c *.h 2> cppcheck.log

.PHONY: all clean check install tags test techdebt
