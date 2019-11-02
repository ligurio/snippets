# testicase

is a tool allows to store testcases as a code

- Consume testcases described with [Gherkin](https://docs.cucumber.io/gherkin) syntax
- Produce JUnit-compliant output

### Usage

```
$ go build
$ ./testicase -in sample.feature
$ ./testicase -in sample.feature -tags "a b c" -out report.xml
```

### Who uses testcases-as-a-code:

- Mozilla: [MozTrap testcase formats](https://moztrap.readthedocs.io/en/latest/userguide/ui/import.html)
- Canonical: Ubuntu Linux
  - Wiki: [TestCase Format](https://wiki.ubuntu.com/Testing/TestCaseFormat), [TestCase](https://wiki.ubuntu.com/QATeam/TestCase), [Writing TestCases](https://wiki.ubuntu.com/QATeam/ContributingTestcases/Manual/Writing)
  - [ubuntu-manual-tests](https://launchpad.net/ubuntu-manual-tests/)
  - [test-case-format](https://github.com/javier-lopez/learn/blob/master/sh/tools/test-case-format)
- [TestRail](http://automation-remarks.com/2018/test-cases-as-a-code/index.html)
- [Linaro](https://github.com/Linaro/test-definitions)
- [Chromium (Blink)](https://cs.chromium.org/chromium/src/third_party/blink/manual_tests/?g=0)
- [xmind2testlink](https://github.com/tobyqin/xmind2testlink)
- [Zephyr](https://github.com/zephyrproject-rtos/qm/tree/master/doc/plans)
- [Gramps](https://github.com/gramps-project/gramps/blob/master/TestPlan.txt)

[How to write good test cases](https://github.com/robotframework/HowToWriteGoodTestCases/blob/master/HowToWriteGoodTestCases.rst)
