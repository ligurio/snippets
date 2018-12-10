CC	=  cc
CFLAGS	=  -I .
CFLAGS	+= -W -Wall -Wextra -Wfloat-equal
CFLAGS	+= -Wundef -Wpointer-arith -Wcast-align -Wshadow
CFLAGS	+= -Wstrict-overflow=5 -Wwrite-strings -Waggregate-return
CFLAGS	+= -Wswitch-enum -Wunreachable-code -Winit-self
CFLAGS	+= -Wno-unused-parameter -Werror -pedantic -O3
LDFLAGS	=

BASE_SOURCES = utils.c test_list.c
SOURCES		= main.c $(BASE_SOURCES)
OBJS		= $(SOURCES:.c=.o)
EXECUTABLE	= runtest

TEST_SOURCES=tests/main.c tests/test_list.c tests/utils.c $(BASE_SOURCES)
TEST_OBJECTS=$(TEST_SOURCES:.c=.o)
TEST_EXECUTABLE=runtest-test
TEST_LDFLAGS=-lm -lrt -lpthread
TEST_LIBSTATIC=-lcheck -lsubunit

TEST_DATA=$(shell echo `pwd`/tests/data)

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

tests: $(TEST_SOURCES) $(TEST_EXECUTABLE)

$(TEST_EXECUTABLE): $(TEST_OBJECTS)
	$(CC) $(LDFLAGS) $(TEST_LDFLAGS) $(TEST_OBJECTS) -o $@ $(TEST_LIBSTATIC)

check: $(TEST_EXECUTABLE)
	./$(TEST_EXECUTABLE) -d $(TEST_DATA)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(EXECUTABLE) $(OBJS) $(TEST_EXECUTABLE) $(TEST_OBJECTS)

.PHONY: clean tests
