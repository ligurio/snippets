### Подддержка русского языка для codespell

Есть удобный скрипт для проверки опечаток `codespell` [^4].
С ним удобно проверять опечатки именно в коде, потому что в отличие
от утилит типа `ispell` или `aspell` у неё маленький процент ложных
срабатываний. Однако `codespell` поддерживает только английский язык.
Правда и в коде достаточно (на моей практике по крайней мере)
редко пишут комментарии на русском языке, но тем не менее это бывает.
Для проверки опечаток `codespell` использует словарь, в котором
слову с опечаткой ставится в соответствие слово без опечатки.

Пример таких пар:

```
cooridate->coordinate
cooridated->coordinated
cooridates->coordinates
cooridinate->coordinate
cooridinated->coordinated
cooridinates->coordinates
cooridinating->coordinating
cooridination->coordination
```

Чтобы сделать словарь для русского языка надо было где-то найти
источник таких соответствий.

Денис Юричев (да, он автор "SAT/SMT by example" и "Reverse Engineering for
Beginners") придумал способ поиска опечаток в Википедии.
Он выгрузил дамп статей на русском языке в Википедии [^5] и пропустил
все статьи через скрипт. Как работает скрипт:

> What my script just takes all words from Wikipedia dump and
> build a dictionary, somewhat resembling to search index, but my
> dictionary reflects number of occurrences within Wikipedia dump
> (i.e., word popularity). Words in dictionary are limited by
> 6 characters, all shorter words are ignored. Then the script
> divides the whole dictionary by two parts. The first part is
> called "probably correct words" and contains words which are
> very popular, i.e., occurred most frequently (more than 200-300
> times in the whole Wikipedia dump). The second part is called
> "words to check" and contain rare words, which occurred less
> than 10 times in the dump.
>
> Then the script takes each "word to check" and calculates
> distance between it and an each word in the "probably correct
> words" dictionary. If the resulting distance is 1 or 2,
> it may be a typo and it's reported.

В результате работы скрипта получился список с парами "слово с опечаткой" и
"слово без опечатки". А ведь именно такие пары использует `codespell`.
Я немного изменил скрипт Дениса, чтобы он записал эти пары в формате, который
понимает `codespell` и теперь `codespell` можно использовать для текстов на
русском языке. У меня есть большой текст, который я давно отсканировал, и
распознал и отформатировал в TeX. В этом тексте я часть опечаток нашел глазами
во время вычитки, часть опечаток нашел с помощью спеллчекера, встроенного в MS
Word и часть нашел с помощью `aspell`. Был удивлен, когда `codespell` с полученным
словарем нашел еще с десяток опечаток. Но, к слову, были и ложные срабатывания.

- [dictionary_ru.txt](dictionary_ru.txt) - словарь для `codespell`
- [get_typos.py](get_typos.py) - скрипт Дениса Юричева, я исправил форматирование и адаптировал для Python 3.
- [RU_typos.txt](RU_typos.txt) - список все пар, которые получил Денис на дампе Википедии.

[^1]: https://yurichev.com/blog/fuzzy_string/
[^2]: https://yurichev.com/news/20210719_wikipedia_typos_RU_UA/
[^3]: http://norvig.com/spell-correct.html
[^4]: https://github.com/codespell-project/codespell/tree/master/codespell_lib/data
[^5]: https://dumps.wikimedia.org/enwiki/latest/enwiki-latest-pages-meta-current.xml.bz2
[^6]: https://yurichev.com/news/20210719_wikipedia_typos_RU_UA/files/
