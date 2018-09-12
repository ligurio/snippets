PREFIX	  ?= /usr/local

CC        ?= gcc
CFLAGS	  += -Og -g
CFLAGS	  += -Wall -Wextra -Wfloat-equal -Wundef
CFLAGS	  += -Wpointer-arith -Wcast-align -Wshadow
CFLAGS	  += -Wstrict-overflow=5 -Wwrite-strings -Waggregate-return
CFLAGS	  += -Wswitch-enum -Wunreachable-code -Winit-self
LDFLAGS   += -lexpat -g

SRCS	= testres.c parse_common.c parse_junit.c \
	parse_subunit_v2.c parse_subunit_v1.c \
	parse_testanything.c ui_common.c
OBJ	= $(patsubst %.c,%.o,$(SRCS))
PLIST	= $(patsubst %.c,%.plist,$(SRCS))
PROJECT = testres
BIN	= $(PROJECT)
CGIBIN	= $(BIN)-static
CGIDIR	= /var/www/cgi-bin

all: $(BIN) $(CGIBIN)

$(BIN): $(OBJ) $(SRCS)
	$(CC) -L/usr/local/lib $(SRCS) -o $(BIN) $(LDFLAGS)

$(CGIBIN): $(OBJ) $(SRCS)
	$(CC) -static -L/usr/local/lib $(SRCS) -o $(CGIBIN) $(LDFLAGS)

$(OBJ): %.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(PLIST): %.plist: %.c
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
	rm -f $(BIN) $(CGIBIN) $(OBJ) $(PLIST) *.{BAK,core} cppcheck.log tags

release: $(BIN) $(CGIBIN)
	@strip --strip-all --verbose $(BIN)-static
	@strip --strip-all --verbose $(BIN)
	@tar cvzf $(PROJECT).tgz $(BIN)-static $(BIN) $(BIN).1

techdebt:
	@find . -name '*.[ch]' | xargs grep -E " TODO|FIXME"

check: cppcheck clang-analyzer

clang-analyzer: $(PLIST)

cppcheck: $(SRCS)
	@cppcheck --template "{file} ({line}): {severity} ({id}): {message}" \
		--enable=warning,portability,performance \
		--suppress=redundantAssignment \
		--suppress=uselessAssignmentPtrArg \
		--suppress=incorrectStringBooleanError \
		--std=c89 $(SRCS)
fmt:
	@$(foreach SRC,$(SRCS),indent -ci4 -di1 -nlp $(SRC);)

.PHONY: all clean check install tags test techdebt
.PHONY: cppcheck clang-analyzer
