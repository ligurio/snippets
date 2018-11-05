SRCS = $(sort $(wildcard *.c))
OBJS = $(SRCS:.c=.o)

CFLAGS = -Os -Wall -Werror -Wshadow -Wno-div-by-zero
LDFLAGS = -static
LIBS += -lpthread


all: microb

clean:
	rm -f $(OBJS) microb

test: all
	./microb

microb: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: build clean
