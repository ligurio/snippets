PREFIX	  ?= /usr/local

CC        ?= gcc
CFLAGS	  += -Og -g
CFLAGS	  += -Wall -Wextra -Wfloat-equal -Wundef
CFLAGS	  += -Wpointer-arith -Wcast-align -Wshadow
CFLAGS	  += -Wstrict-overflow=5 -Wwrite-strings -Waggregate-return
CFLAGS	  += -Wswitch-enum -Wunreachable-code -Winit-self
LDFLAGS   += -lgsl -g

SRCS	= deviation.c
OBJ	= $(patsubst %.c,%.o,$(SRCS))
PLIST	= $(patsubst %.c,%.plist,$(SRCS))
PROJECT = deviation
BIN	= $(PROJECT)
MAN	= $(PROJECT).1

all: $(BIN)

$(BIN): $(OBJ) $(SRCS)
	$(CC) -L/usr/local/lib $(SRCS) -o $(BIN) $(LDFLAGS)

$(OBJ): %.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(PLIST): %.plist: %.c
	@clang --analyze $<

install: all
	@install -m 0755 $(BIN) $(PREFIX)/bin

uninstall:
	@rm -f $(PREFIX)/bin/$(BIN)

test:
	@make -C tests

tags:
	@find . -name '*.[ch]' | xargs ctags

clean:
	rm -f $(BIN) $(OBJ) $(PLIST) cppcheck.log tags

techdebt:
	@find . -name '*.[ch]' | xargs grep -E " TODO|FIXME"

check: cppcheck clang-analyzer mandoc-lint

clang-analyzer: $(PLIST)

mandoc-lint: $(MAN)
	mandoc -T lint $(MAN)

cppcheck: $(SRCS)
	@cppcheck --template "{file} ({line}): {severity} ({id}): {message}" \
		--enable=warning,portability,performance \
		--std=c89 $(SRCS)
fmt:
	@$(foreach SRC,$(SRCS), $(indent -ci4 -di1 -nlp $(SRC);))

.PHONY: all clean check install tags test techdebt
.PHONY: cppcheck clang-analyzer fmt
