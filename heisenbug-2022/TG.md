Материалы к докладу "Делаем фаззер для Lua на основе libFuzzer"

Примеры кода из доклада - https://github.com/ligurio/snippets/tree/master/heisenbug-2022

Все примеры можно запустить, см. комментарии в файлах:

- `add_tests.py` - тестирование функции сложения с помощью примеров, Hypothesis и Atheris
- `trace-pc.c` - пример инструментирования программы в Clang для предоставления обратной связи
- `libfuzzer-example.c` - пример фаззера для libFuzzer

Здесь опубликую модуль для фаззинга Lua - https://github.com/ligurio/luzer/

Слайды - https://bronevichok.ru/papers/2022-Heisenbug-coverage-guided-lua-fuzzing.pdf

Дополнительные ссылки

- Hypothesis - расширение для тестирования с помощью свойств в Python
- Atheris - фаззер с обратной связью для Python на основе libFuzzer
- Fuzzing Python with Atheris - доклад про Atheris
- How the Atheris Python Fuzzer Works
- Technical "whitepaper" for afl-fuzz
- lua-quickcheck
- afl-lua
- libFuzzer
- Пример интеграции Lua с AFL без изменения интерпретатора -
https://gist.github.com/stevenjohnstone/2236f632bb58697311cd01ea1cafbbc6
Будет работать, но не так эффективно, потому что не инструментируются полезные инструкции в Lua ВМ.

Доклад, в котором Tavis Ormandy описал идею использования обратной связи, чтобы сделать фаззинг эффективнее - "Making Software Dumber - Tavis Ormandy"

- OSS Fuzz:
  - https://github.com/google/oss-fuzz
  - Доклад [ClusterFuzz: Fuzzing at Google Scale][clusterfuzz]

[hypothesis-python]: https://hypothesis.readthedocs.io/en/latest/quickstart.html
[atheris-python]: https://github.com/google/atheris
[atheris-talk]: https://www.youtube.com/watch?v=OE3PTAvVIPU
[atheris-post]: https://security.googleblog.com/2020/12/how-atheris-python-fuzzer-works.html
[afl-whitepaper]: https://lcamtuf.coredump.cx/afl/technical_details.txt
[lqc]: https://github.com/luc-tielen/lua-quickcheck
[afl-lua]: https://github.com/stevenjohnstone/afl-lua
[libfuzzer]: https://llvm.org/docs/LibFuzzer.html
[making_software_dumber_slides]: http://taviso.decsystem.org/making_software_dumber.pdf
[making_software_dumber_talk]: https://www.youtube.com/watch?v=CjGGtbF3oNs
[SanitizerCoverage]: https://clang.llvm.org/docs/SanitizerCoverage.html
[fuzzing_at_scale]: https://security.googleblog.com/2011/08/fuzzing-at-scale.html
[clusterfuzz]: https://i.blackhat.com/eu-19/Wednesday/eu-19-Arya-ClusterFuzz-Fuzzing-At-Google-Scale.pdf
