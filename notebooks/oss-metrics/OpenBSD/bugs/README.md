### OpenBSD bugtracker

original: dfd731

Немного статистики:
Архив bugs@ включает в себя около 32 тысяч писем в 18 тысячах тредов.
То есть с 1998 года накопилось 18 тысяч репортов.

### TODO

- извлекать прикрепленные файлы из писем и добавлять к тикетам
- какой-то из тикетов в бинарном формате и на нем импорт ломается

### Архив списка рассылки

Есть всего несколько источников для создания локального архива списка рассылки.
Первый это https://marc.info/?l=openbsd-bugs, второй это https://lists.openbsd.org.

```
$ git clone https://github.com/gaalcaras/mailingListScraper
$ cd mailingListScraper
$ virtualenv pip
$ pip install -r requirements.txt

$ sudo apt-get install python3-venv
$ python3 -m venv pip
$ source pip/bin/activate
$ ./pip/bin/pip install -r requirements.txt
$ python3 ./pip/bin/scrapy crawl marc -a mlist=print
$ python3 ./pip/bin/scrapy crawl marc -a year=2018 -a mlist=openbsd-bugs -a body=false
$ python3 ./pip/bin/scrapy crawl marc -a year=1998:2018 -a mlist=openbsd-bugs
```

### Импорт

- удалить бинарные данные:
	data-scraping/data/openbsd-bugs1999Bodies.xml +22295
	data-scraping/data/openbsd-bugs2014Bodies.xml +69893
- создать почтовый адрес для обработки тикетов (liebfrautits@gmail.com?)
- подписать этот адрес на рассылку bugs@openbsd.org
- настроить fdm для обработки писем от bugs@openbsd.org
```
fossil clone https://bronevichok.ru/cgi-bin/b.cgi tickets.fossil
fossil open tickets.fossil
cat sample1.eml | mail2fossil.py -b https://bronevichok.ru/cgi-bin/b.cgi/index -R tickets.fossil
```

### Настройка Fossil SCM

- создать файлы устройств /dev/null и /dev/random для CGI
WARNING: Device "/dev/null" is not available for reading and writing.
WARNING: Device "/dev/urandom" is not available for reading. This means that the pseudo-random number generator used by SQLite will be poorly seeded.
- импортировать тикеты
```
		$ fossil ticket add title "title" comment "$(cat bugs)"
```
- сделать репозиторий приватным /takeitprivate
- включить admin_log и access_log в /setup_settings
- настроить шаблоны страниц в /tktsetup
- переименовать репозиторий в /setup_config
- включить поиск тикетов и создать индекс /srchsetup
- включить WebCache
- поле Category со значениями из [sendbug](https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/sendbug/sendbug.c)
- поле Platform со значениями из [sendbug](https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/sendbug/sendbug.c)
- значение в поле Resolution "No answer from reporter"
- включить премодерацию изменений для тикетов? /setup_modreq
- протестировать скриптом https://www.fossil-scm.org/fossil/file/tools/fossil-stress.tcl

### Жизненный цикл дефекта

- закрывать все баги, в которых последний ответ был год назад
- TODO: при упоминании бага в tech@openbsd.org переводить дефект в статус Review
- TODO: закрывать баг при упоминании бага в source-changes@openbsd.org
- Rules https://wiki.ubuntu.com/HelpingWithBugs

### Tips

- Подписка по RSS https://www.fossil-scm.org/xfer/help?cmd=/timeline.rss
- Создать локальную копию ```fossil clone https://bronevichok.ru/cgi-bin/b.cgi/index tickets.fossil```
- Управление тикетами из командной строки https://www.fossil-scm.org/xfer/help?cmd=ticket
