# This way everything works as expected ever for
# `make -C /path/to/project` or
# `make -f /path/to/project/Makefile`.
MAKEFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
PROJECT_DIR := $(patsubst %/,%,$(dir $(MAKEFILE_PATH)))
LUACOV_REPORT := $(PROJECT_DIR)/luacov.report.out
LUACOV_STATS := $(PROJECT_DIR)/luacov.stats.out

all: test

# The template (ldoc.tpl) is written using tarantool specific
# functions like string.split(), string.endswith(), so we run
# ldoc using tarantool.
apidoc:
	ldoc -c $(PROJECT_DIR)/doc/ldoc/config.ld \
             -d $(PROJECT_DIR)/doc/apidoc/ $(PROJECT_DIR)/jepsen

check: luacheck

luacheck:
	luacheck --config .luacheckrc --codes .

test:
	luatest -v

$(LUACOV_STATS): test

coverage: $(LUACOV_STATS)
	sed -i -e 's@'"$$(realpath .)"'/@@' $(LUACOV_STATS)
	cd $(PROJECT_DIR) && luacov .
	grep -A999 '^Summary' $(LUACOV_REPORT)

coveralls: $(LUACOV_STATS)
	echo "Send code coverage data to the coveralls.io service"
	luacov-coveralls --include ^jepsen --verbose --repo-token ${GITHUB_TOKEN}

.PHONY: test coveralls coverage luacheck check apidoc
