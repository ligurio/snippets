- CGI support
	- https://git.zx2c4.com/cgit/
	- https://github.com/kristapsdz/sblg
	- https://man.openbsd.org/man.cgi.8
	- https://man.openbsd.org/bgplg.8
	- https://github.com/reyk/meta-data/
- filters:
	- https://git.zx2c4.com/cgit/tree/filters
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
- сделать сортировку репортов по времени
- plotting:
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
- User Defined Attributes
	https://taskwarrior.org/docs/udas.html
	https://taskwarrior.org/docs/terminology.html#uda
- в список репортов добавить название файла и прогресс-бары (pass-rate) [#######     ] 51%
- ML
	- https://github.com/attractivechaos/kann
	- https://github.com/tiny-dnn/tiny-dnn
	- https://github.com/pjreddie/darknet 
	- https://github.com/jppbsi/LibDEEP
	- https://codeplea.com/genann
	- http://leenissen.dk/fann/wp/
	- https://100.github.io/Cranium/
	- http://chasen.org/~taku/software/TinySVM/#source
	- https://members.loria.fr/YGuermeur/
	- https://leon.bottou.org/projects/sgd
	- http://www.svms.org/software.html
	- https://github.com/simonwalton/libqcat
	- https://github.com/cvjena/libmaxdiv/tree/master/maxdiv/libmaxdiv
	- https://seclab.cs.ucsb.edu/academic/projects/projects/libanomaly/
	- http://dlib.net/ml.html
	- https://pjreddie.com/darknet/
	- https://github.com/siavashserver/neonrvm
	- http://www.support-vector-machines.org/SVM_soft.html
	- https://www.csie.ntu.edu.tw/~cjlin/libsvm/
	- http://www-ai.cs.uni-dortmund.de/SOFTWARE/MYSVM/index.html
	- http://svmlight.joachims.org/

- используй strdup()

### Тесты

https://github.com/mtreinish/junitxml2subunit/tree/master/tests/examples
