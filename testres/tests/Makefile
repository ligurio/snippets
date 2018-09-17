
all: test-unit test-regress test-fuzz

test-unit:
	$(MAKE) -C unit

test-regress:
	$(MAKE) -C regress

test-fuzz:
	$(MAKE) -C fuzz

test-load:
	$(MAKE) -C load

clean:
	$(MAKE) -C unit clean
	$(MAKE) -C regress clean
	$(MAKE) -C fuzz clean

.PHONY: all test-unit test-regress test-fuzz test-load clean
