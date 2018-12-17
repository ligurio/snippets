CC	=  cc
CFLAGS	+= -W -Wall -Wextra -Wfloat-equal
CFLAGS	+= -Wundef -Wpointer-arith -Wcast-align -Wshadow
CFLAGS	+= -Wstrict-overflow=5 -Wwrite-strings -Waggregate-return
CFLAGS	+= -Wswitch-enum -Wunreachable-code -Winit-self
CFLAGS	+= -Wno-unused-parameter -Werror -pedantic -O3

SOURCES		= tt-cc.c
OBJS		= $(SOURCES:.c=.o)
EXECUTABLE	= tt-cc

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(EXECUTABLE) $(OBJS)

.PHONY: clean tests
