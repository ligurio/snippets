## testres

A hyperfast web frontend for software testing results written in C.

It builds and runs on OpenBSD, Linux, and Mac OS X.

If you have any comments or patches, please feel free to post them here or
notify me by e-mail.

### Usage

```
$ mkdir build
$ cd build
$ cmake .. -DCMAKE_BUILD_TYPE=RELEASE
$ cmake .. -DCMAKE_BUILD_TYPE=DEBUG
$ make
$ bin/testres -s samples/junit.xml
```

### Authors

Developed with passion by [Sergey Bronnikov](https://bronevichok.ru/) and great
open source [contributors](https://github.com/ligurio/testres/contributors).
