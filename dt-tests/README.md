### Datetime tests

is a project with testing different implementations of libraries that works
with date and time. Tests implemented using Python and
[Atheris](https://github.com/google/atheris).

TODO: use Hypothesis

### Tests

- Date and time formatting (`strftime`).
- Date and time parsing (`strptime`).
- Date and time math.
- http://howardhinnant.github.io/date_algorithms.html

### Implementations

1. Python datetime library, https://docs.python.org/3/library/datetime.html
1. dateutils, https://github.com/hroptatyr/dateutils
1. pdd, https://github.com/jarun/pdd
1. yest, https://sourceforge.net/projects/yest/
1. dateexpr, http://www.eskimo.com/~scs/src/#dateexpr
1. allanfalloon's dateutils, https://github.com/alanfalloon/dateutils
1. Bloomberg bldt, https://bloomberg.github.io/bde-resources/doxygen/bde_api_prod/classbdlt_1_1Datetime.html
1. Boost's datetime, https://www.boost.org/doc/libs/1_62_0/doc/html/date_time.html
1. [FormalV](https://gitlab.com/formalv/formalv), [2209.14227] FV Time: a formally verified Coq library, https://arxiv.org/abs/2209.14227
1. https://github.com/HowardHinnant/date

### TODO

- https://www.epochconverter.com/weeknumbers
- https://www.epochconverter.com/
- https://github.com/HowardHinnant/date/tree/master/test/date_test
- https://github.com/CppCon/CppCon2015/blob/master/Presentations/A%20C++14%20Approach%20to%20Dates%20and%20Times/A%20C++14%20Approach%20to%20Dates%20and%20Times%20-%20Howard%20Hinnant%20-%20CppCon%202015.pdf
- CppCon 2015: Howard Hinnant "A C++14 approach to dates and times", https://www.youtube.com/watch?v=tzyGjOm8AKo
- "On the proof of correctness of a calendar program" -- Leslie Lamport, https://dl.acm.org/doi/10.1145/359156.359160
