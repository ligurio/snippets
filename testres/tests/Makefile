
all: test-unit test-regress test-fuzz

test-unit:
	$(MAKE) -C unit

test-regress:
	$(MAKE) -C regress

test-fuzz:
	$(MAKE) -C fuzz

clean:
	$(MAKE) -C unit clean
	$(MAKE) -C regress clean
	$(MAKE) -C fuzz clean

.PHONY: all test-unit test-regress test-fuzz clean
