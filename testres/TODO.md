- CGI support
	- https://git.zx2c4.com/cgit/
	- https://github.com/kristapsdz/sblg
	- https://man.openbsd.org/man.cgi.8
	- https://man.openbsd.org/bgplg.8
	- https://github.com/reyk/meta-data/
- добавить pledge(), capsicum() (см. https://kristaps.bsd.lv/lowdown/)
- сделать сортировку репортов по времени
- используй strdup()


- thttpd.conf:
```
host=127.0.0.1
port=8080
user=sergeyb
dir=/home/sergeyb/sources/snippets/testres/
cgipat=*
```
- testres.cgi:
```
#!/bin/sh

PWD=$(pwd)
#exec $PWD/testres -s $PWD/web/junit.xml
exec $PWD/testres -s $PWD/web/
```
