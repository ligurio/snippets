TOP_SRC_DIR = ..

CC 	?= gcc
CFLAGS  += -I/usr/local/include/ -I$(TOP_SRC_DIR)
LDFLAGS += -L/usr/local/lib -lexpat -lcmocka
TEST_BIN = testres_tests
SRCS	 = testres_tests.c \
		$(TOP_SRC_DIR)/parse_testanything.c \
		$(TOP_SRC_DIR)/parse_junit.c \
		$(TOP_SRC_DIR)/parse_subunit_v1.c \
		$(TOP_SRC_DIR)/parse_subunit_v2.c \
		$(TOP_SRC_DIR)/parse_common.c
OBJ     = $(patsubst %.c,%.o,$(SRCS))
BIN	 = testres

SAMPLE_FILE_JUNIT = "samples/junit.xml"
SAMPLE_FILE_JUNIT_MIN = "samples/junit-min.xml"
SAMPLE_FILE_SUBUNIT_V1 = "samples/subunit_v1.subunit"
SAMPLE_FILE_SUBUNIT_V1_MIN = "samples/subunit_v1-min.subunit"
SAMPLE_FILE_SUBUNIT_V2 = "samples/subunit_v2.subunit"
SAMPLE_FILE_SUBUNIT_V2_MIN = "samples/subunit_v2-min.subunit"
SAMPLE_FILE_TESTANYTHING = "samples/testanything.tap"
SAMPLE_FILE_TESTANYTHING_MIN = "samples/testanything-min.tap"

TEST_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
AFL_IN = $(TEST_DIR)/afl-in
AFL_OUT = $(TEST_DIR)/afl-out

VALGRIND_OPT = --leak-check=yes --leak-check=full --show-leak-kinds=all

all: test-unit test-module

$(TEST_BIN): $(OBJ)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS)

$(OBJ): %.o : %.c
	$(CC) -c -o $@ $< $(CFLAGS)

test-unit: $(TEST_BIN)
	./$(TEST_BIN)

build_app:
	$(MAKE) -C $(TOP_SRC_DIR)

test-module: build_app
	@-valgrind $(VALGRIND_OPT) $(TOP_SRC_DIR)/$(BIN) -s $(SAMPLE_FILE_TESTANYTHING)
	@-valgrind $(VALGRIND_OPT) $(TOP_SRC_DIR)/$(BIN) -s $(SAMPLE_FILE_SUBUNIT_V1)
	@-valgrind $(VALGRIND_OPT) $(TOP_SRC_DIR)/$(BIN) -s $(SAMPLE_FILE_SUBUNIT_V2)
	@-valgrind $(VALGRIND_OPT) $(TOP_SRC_DIR)/$(BIN) -s $(SAMPLE_FILE_JUNIT)

test-fuzz:
	@make -C $(TOP_SRC_DIR) clean
	@-mkdir $(AFL_IN) $(AFL_OUT)
	@cp $(SAMPLE_FILE_JUNIT_MIN) $(AFL_IN)
	@cp $(SAMPLE_FILE_SUBUNIT_V1_MIN) $(AFL_IN)
	@cp $(SAMPLE_FILE_SUBUNIT_V2_MIN) $(AFL_IN)
	@cp $(SAMPLE_FILE_TESTANYTHING_MIN) $(AFL_IN)
	@CC=afl-clang make -C $(TOP_SRC_DIR)
	@AFL_USE_MSAN=1 AFL_USE_ASAN=1 AFL_EXIT_WHEN_DONE=1 \
	afl-fuzz -i $(AFL_IN) -o $(AFL_OUT) -- $(TOP_SRC_DIR)/$(BIN) -s @@

clean:
	rm -rf $(OBJ) $(TEST_BIN) $(AFL_IN) $(AFL_OUT) *.core

.PHONY: all test-unit test-module test-fuzz clean
