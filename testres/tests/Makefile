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

all: test

$(TEST_BIN): $(OBJ)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) $(LDFLAGS)

build_app:
	$(MAKE) -C $(TOP_SRC_DIR)/

test: $(TEST_BIN) build_app
	./$(TEST_BIN)

clean:
	rm -f $(OBJ) $(TEST_BIN)
