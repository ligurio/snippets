TOP_SRC_DIR = ../

CC = gcc
CFLAGS += -I/usr/local/include/
LDFLAGS = -L/usr/local/lib -lcmocka
TEST_BIN = testres_tests

OBJ = testres_tests.o

all: build_app $(TEST_BIN)

$(TEST_BIN): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

build_app:
	$(MAKE) -C $(TOP_SRC_DIR)/

clean:
	rm -f $(OBJ) $(TEST_BIN)

check: all
	./$(TEST_BIN)
