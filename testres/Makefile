CFLAGS		= -O3
SRCS		= testres.c parse_junit.c parse_testanything.c
BIN		= testres.cgi

CGIDIR		= /var/www/cgi-bin

all: testres.cgi

testres.cgi: $(SRCS)
	$(CC) -static -L/usr/local/lib $(SRCS) -o $(BIN) -lexpat -lz

install: all
	mkdir -p $(CGIDIR)
	install -m 0755 testres.cgi $(CGIDIR)

clean:
	rm -f $(BIN)

static-analysis:
	cppcheck *

.PHONY: install
