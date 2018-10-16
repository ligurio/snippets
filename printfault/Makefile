LIBNAME = printfault

all: test
	
test: $(LIBNAME).so
	@gcc test-sample.c -o test-sample
	@-LD_PRELOAD=./$(LIBNAME).so ./test-sample

$(LIBNAME).so: 
	@gcc $(LIBNAME).c -I/usr/local/include -L/usr/local/lib -pthread -lunwind -lunwind-x86_64 -shared -fPIC -o $@

clean:
	rm -f test-sample $(LIBNAME).so
