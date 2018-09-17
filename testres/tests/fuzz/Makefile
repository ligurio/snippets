TOP_SRC_DIR = ../..

BIN = testres
SAMPLE_DIR = "../samples"
SAMPLE_FILE_JUNIT_MIN = $(SAMPLE_DIR)/"junit-min.xml"
SAMPLE_FILE_SUBUNIT_V1_MIN = $(SAMPLE_DIR)/"subunit_v1-min.subunit"
SAMPLE_FILE_SUBUNIT_V2_MIN = $(SAMPLE_DIR)/"subunit_v2-min.subunit"
SAMPLE_FILE_TESTANYTHING_MIN = $(SAMPLE_DIR)/"testanything-min.tap"

AFL_IN = "afl-in"
AFL_OUT = "afl-out"

all: test-afl

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
	$(RM) -rf $(AFL_IN) $(AFL_OUT)

.PHONY: all test-afl clean
