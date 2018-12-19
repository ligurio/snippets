LIBNAME = tt-coverage

all: $(LIBNAME).so

$(LIBNAME).so: $(LIBNAME).c
	@gcc $(LIBNAME).c -shared -fPIC -o $@

clean:
	rm -f $(LIBNAME).so
