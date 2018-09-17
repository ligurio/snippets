SERVER	?= "http://localhost:8080"
URL	?= "testres.cgi?index"

all: test-load

test-load:
	ab -k -c 100 -n 1000 $(SERVER)/$(URL)

.PHONY: all test-load
