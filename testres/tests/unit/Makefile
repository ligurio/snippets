TOP_SRC_DIR = ../..

CC 	?= gcc
CFLAGS  += -I/usr/local/include/ -I$(TOP_SRC_DIR)
LDFLAGS += -L/usr/local/lib -lexpat -lcmocka
TEST_BIN = testres_tests
SRCS	 = testres_tests.c \
		$(TOP_SRC_DIR)/parse_testanything.c \
		$(TOP_SRC_DIR)/parse_junit.c \
		$(TOP_SRC_DIR)/parse_subunit_v1.c \
		$(TOP_SRC_DIR)/parse_subunit_v2.c \
		$(TOP_SRC_DIR)/parse_common.c \
		$(TOP_SRC_DIR)/sha1.c
OBJ     = $(patsubst %.c,%.o,$(SRCS))

all: test-unit

$(TEST_BIN): $(OBJ)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS)

$(OBJ): %.o : %.c
	$(CC) -c -o $@ $< $(CFLAGS)

test-unit: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	rm -f $(OBJ) $(TEST_BIN) *.core

.PHONY: all test-unit clean
