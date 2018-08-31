TOP_SRC_DIR = ..

CC 	 = gcc
CFLAGS  += -I/usr/local/include/ -I$(TOP_SRC_DIR)
LDFLAGS += -L/usr/local/lib -lexpat -lcmocka
TEST_BIN = testres_tests
SRCS	 = testres_tests.c
OBJ 	 = testres_tests.o			\
	   $(TOP_SRC_DIR)/parse_testanything.o 	\
	   $(TOP_SRC_DIR)/parse_junit.o 	\
           $(TOP_SRC_DIR)/parse_subunit_v2.o	\
           $(TOP_SRC_DIR)/parse_common.o	\
           $(TOP_SRC_DIR)/manage_tests.o
BIN	 = testres.cgi

SAMPLE_FILE_JUNIT = "samples/junit/junit-sample-1.xml"
SAMPLE_FILE_SUBUNIT_V2 = "samples/subunit/subunit-sample-02.subunit"
SAMPLE_FILE_TESTANYTHING = "samples/testanything/tap-sample-01.tap"

VALGRIND_OPT = --leak-check=yes --leak-check=full --show-leak-kinds=all

all: test-unit test-module

$(TEST_BIN): $(OBJ)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) $(LDFLAGS)

build_app:
	$(MAKE) -C $(TOP_SRC_DIR)/

test-unit: $(TEST_BIN) build_app
	./$(TEST_BIN)

test-module: build_app
	@valgrind $(VALGRIND_OPT) $(TOP_SRC_DIR)/$(BIN) -f $(SAMPLE_FILE_TESTANYTHING)
	@valgrind $(VALGRIND_OPT) $(TOP_SRC_DIR)/$(BIN) -f $(SAMPLE_FILE_SUBUNIT_V2)
	@valgrind $(VALGRIND_OPT) $(TOP_SRC_DIR)/$(BIN) -f $(SAMPLE_FILE_JUNIT)

clean:
	rm -f $(OBJ) $(TEST_BIN)
