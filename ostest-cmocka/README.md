# ostest-cmocka

[os-test](https://gitlab.com/sortix/os-test) is a set of test suites for POSIX operating systems designed to make it easy to compare differences between operating systems and to find operating system bugs. It consists of test suites that focus on different operating system areas.

This repository contains a port of os-test suites to [CMocka](https://cmocka.org/).

### Changes made:

- `err()` -> `fail_msg()`
- `errx()` -> `fail_msg()`
- `printf()` -> `fprintf()`
