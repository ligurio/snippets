## printfault

Sometimes regression tests written on C are just simple binaries which returns
exit code and nothing else. In such cases it is difficult to figure out a
reason of the crash without a stacktrace. ```printfault``` is preloadable
library that will print a stacktrace of the program when it crashes or upon
receiving any other relevant signal.

stacktrace printing can be implemented with GDB: ```gdb -q ./sample --batch -n
-ex run -ex thread -ex backtrace -ex "set pagination off" -ex "set confirm off"
-ex quit```. But this method requires GDB and slows down a bit of program
execution.

### Usage

```
$ make build
$ gcc -O0 -g3 test-sample.c -o test-sample
$ LD_PRELOAD=./printfault.so ./test-sample
Caught signal 11 (Segmentation fault) in program ??? [12297]

thread frame  IP              function
[0045] 00000: 0x55d40e78460d: main()+0x13
[0045] 00001: 0x7f71e63f4b97: __libc_start_main()+0xe7
[0045] 00002: 0x55d40e78451a: _start()+0x2a

Backtrace: 0x55d40e78460d 0x7f71e63f4b97 0x55d40e78451a
Segmentation fault (core dumped)
```

Tested on Linux, OpenBSD.
