# testicase

handy tool to pass manual testcases.

- Support of testplans with format described in the [829-2008 - IEEE Standard
for Software and System Test
Documentation](https://standards.ieee.org/findstds/standard/829-2008.html)
- Produce JUnit and TestAnythingProtocol compliant output

### Usage

```
$ go build main.go
$ ./main -file sample.yaml
```

### See also

- Mozilla:
  - [MozTrap testcase formats](https://moztrap.readthedocs.io/en/latest/userguide/ui/import.html)
- Ubuntu Linux:
  - [TestCase Format](https://wiki.ubuntu.com/Testing/TestCaseFormat)
  - [TestCase](https://wiki.ubuntu.com/QATeam/TestCase)
  - [Writing TestCases](https://wiki.ubuntu.com/QATeam/ContributingTestcases/Manual/Writing)
  - [Ubuntu Manual TestCases](https://launchpad.net/ubuntu-manual-tests/)
  - https://github.com/javier-lopez/learn/blob/master/sh/tools/test-case-format
- TestRail:
  - http://automation-remarks.com/2018/test-cases-as-a-code/index.html
- Linaro:
  - https://github.com/Linaro/test-definitions
- Chromium (Blink):
  - https://cs.chromium.org/chromium/src/third_party/blink/manual_tests/?g=0
