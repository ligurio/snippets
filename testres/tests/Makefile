TOP_SRC_DIR = ../..

BIN = testres
SAMPLE_DIR = "../samples"
SAMPLE_FILE_JUNIT_MIN = $(SAMPLE_DIR)/"junit-min.xml"
SAMPLE_FILE_SUBUNIT_V1_MIN = $(SAMPLE_DIR)/"subunit_v1-min.subunit"
SAMPLE_FILE_SUBUNIT_V2_MIN = $(SAMPLE_DIR)/"subunit_v2-min.subunit"
SAMPLE_FILE_TESTANYTHING_MIN = $(SAMPLE_DIR)/"testanything-min.tap"

AFL_IN = "afl-in"
AFL_OUT = "afl-out"

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
		$(TOP_SRC_DIR)/sha1.c \
		$(TOP_SRC_DIR)/cmp.c
OBJ     = $(patsubst %.c,%.o,$(SRCS))

all: test-unit


all: test-afl test-load

test-afl:
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
	rm -rf $(AFL_IN) $(AFL_OUT)

SERVER  ?= "http://localhost:8080"
URL     ?= "testres.cgi?index"

test-load:
	ab -k -c 100 -n 1000 $(SERVER)/$(URL)

$(TEST_BIN): $(OBJ)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS)

$(OBJ): %.o : %.c
	$(CC) -c -o $@ $< $(CFLAGS)

test-unit: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	rm -f $(OBJ) $(TEST_BIN) *.core

.PHONY: all test-afl clean
