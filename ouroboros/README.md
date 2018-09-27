# ouroboros [![Build Status](https://travis-ci.org/ligurio/ouroboros.svg?branch=master)](https://travis-ci.org/ligurio/ouroboros)

<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/c/c8/Ouroboros-simple.svg/2000px-Ouroboros-simple.svg.png" height="100" style="float:left;">

is a simple continuous integration system written in Python.

### Usage

```
$ pip install cs paramiko
$ cat $HOME/.cloudstack.ini
[cloudstack]
endpoint = https://api.exoscale.ch/compute
key = mqqdAD39YWxUrNgIDOvxjEgI4TC-Y0dFkMKSMhCGosJh5o2MouFyR-1buIKLXSTERlW334OIYptfjMLaYs
secret = CuAqaKhtdtwGIg1rGfK4CyrtcPb-0NEvl8LozG4nAYtymuJ2f6XU41Rdat_Zs1Ma1BRBaLXzrEXyZ
$ python ouroboros.py
```

### License

```
/*
 * Copyright (c) 2018 Sergey Bronnikov <sergeyb@bronevichok.ru>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
