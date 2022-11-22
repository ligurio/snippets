## Материалы к докладу "Делаем фаззер для Lua на основе libFuzzer"

### Примеры кода из доклада

Все примеры можно запустить, см. комментарии в файлах:

- `add_tests.py` - тестирование функции сложения с помощью примеров, Hypothesis и Atheris
- `trace-pc.c` - пример инструментирования программы в Clang для предоставления обратной связи
- `libfuzzer-example.c` - пример фаззера для libFuzzer

https://github.com/ligurio/luzer/ - здесь опубликую модуль для фаззинга Lua.

### Дополнительные ссылки:

Примеры кода из доклада: https://github.com/ligurio/snippets/tree/master/heisenbug-2022

- [Hypothesis][hypothesis-python]
- [Atheris][atheris-python]
- [How the Atheris Python Fuzzer Works][atheris-post]
- [Fuzzing Python with Atheris][atheris-talk]
- [Technical "whitepaper" for afl-fuzz][]
- [lua-quickcheck][lqc]
- [afl-lua][afl-lua]
- [libFuzzer][libfuzzer]
- Making Software Dumber - Tavis Ormandy [слайды][making_software_dumber_slides] и [видео][making_software_dumber_talk]
- OSS Fuzz:
  - "As of July 2022, OSS-Fuzz has found over 40,500 bugs in 650 open source projects."
  - https://github.com/google/oss-fuzz
  - Доклад [ClusterFuzz: Fuzzing at Google Scale][clusterfuzz]
- [Sanitize Coverage][SanitizerCoverage]
- Lua 5.1 Reference Manual, 3.8 – The Debug Interface
- [Fuzzing at scale][fuzzing_at_scale] - история о том, как Гугл собрал 20 Тб
  SWF-файлов по всему интернету и использовал их как корпус для фаззинга плеера
  для Flash.

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
