## testres

A hyperfast web frontend for software testing results written in C.

### Примеры CGI приложений

- https://git.zx2c4.com/cgit/
- https://github.com/kristapsdz/sblg
- https://man.openbsd.org/man.cgi.8
- https://man.openbsd.org/bgplg.8
- https://github.com/reyk/meta-data/

### Фичи

https://git.zx2c4.com/cgit/tree/filters

- фильтр для привязанных багов (статус бага, кто ответственный)
- авторизация
- фильтр для комментариев:
	- превращать ссылки на баги или логи в гиперссылки
	- получать статус по багам
- фильтр для заведения бага
- фильтр для построения графиков
- скрипты для БД: flaky?, анализ логов в отчетах
- прогноз по тестам и тестпланам

- добавить pledge(), capsicum() (см. https://kristaps.bsd.lv/lowdown/)
- сделать сортировку репортов
- первая версия с выводом в HTML

### Графики

- http://pages.cs.wisc.edu/~remzi/Zplot/Tcl/
- https://github.com/reddec/svg
- https://wiki.tcl.tk/21144
- http://plplot.sourceforge.net/
- https://github.com/bytebrew/slope
- https://github.com/marmalade/libsvg/
- https://batchloaf.wordpress.com/2011/11/23/simple-data-plotting-from-a-c-console-application-using-svg/
- http://biolpc22.york.ac.uk/linux/plotutils/ascii_chart.c
- https://github.com/ravhed/libsvg
- https://www.gnu.org/software/plotutils/


### Тесты

https://github.com/mtreinish/junitxml2subunit/tree/master/tests/examples
