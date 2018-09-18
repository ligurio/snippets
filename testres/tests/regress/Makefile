TOP_SRC_DIR = ../..

BIN	 = testres
SAMPLE_DIR = "../samples"
SAMPLE_FILE_JUNIT = $(SAMPLE_DIR)/"junit.xml"
SAMPLE_FILE_SUBUNIT_V1 = $(SAMPLE_DIR)/"subunit_v1.subunit"
SAMPLE_FILE_SUBUNIT_V2 = $(SAMPLE_DIR)/"subunit_v2.subunit"
SAMPLE_FILE_TESTANYTHING = $(SAMPLE_DIR)/"testanything.tap"

SHELL_PATH ?= $(SHELL)
SHELL_PATH_SQ = $(subst ','\'',$(SHELL_PATH))

T = $(wildcard t[0-9][0-9][0-9][0-9]-*.sh)

all: test-regress $(T)

build_app:
	$(MAKE) -C $(TOP_SRC_DIR)

test-regress: build_app
	@echo -n "$(SAMPLE_FILE_JUNIT) "
	@-$(TOP_SRC_DIR)/$(BIN) -s $(SAMPLE_FILE_JUNIT) > /dev/null && echo "OK"
	@echo -n "$(SAMPLE_FILE_TESTANYTHING) "
	@-$(TOP_SRC_DIR)/$(BIN) -s $(SAMPLE_FILE_TESTANYTHING) > /dev/null && echo "OK"
	@echo -n "$(SAMPLE_FILE_SUBUNIT_V1) "
	@-$(TOP_SRC_DIR)/$(BIN) -s $(SAMPLE_FILE_SUBUNIT_V1) > /dev/null && echo "OK"
	@echo -n "$(SAMPLE_FILE_SUBUNIT_V2) "
	@-$(TOP_SRC_DIR)/$(BIN) -s $(SAMPLE_FILE_SUBUNIT_V2) > /dev/null && echo "OK"

$(T): build_app
	@echo $@
	@'$(SHELL_PATH_SQ)' $@

clean:
	rm -rf *.core

.PHONY: all test-regress clean build_app $(T)
