# requires musl-gcc, see https://www.musl-libc.org/how.html

all: build_glibc build_musl

build_glibc:
	@echo "Build with GLibc"
	@gcc -fpic -shared -o liba.so a.c
	@gcc -o main main.c
	@./main

build_musl:
	@echo "Build with Musl"
	@musl-gcc -fpic -shared -o liba.so a.c
	@musl-gcc -o main main.c
	@./main

clean:
	rm -f main liba.so
