/*
 * TODO:
 *
 * - background.feature
 * - outlines.feature
 * - steps.feature
 * - tables.feature
 * - tags.feature
 *
 */

package main

import (
	"bufio"
	"encoding/xml"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	gherkin "github.com/cucumber/gherkin-go"
	junit "github.com/ligurio/recidive/formats/junit"
)

const (
	COL_START = "\033[32m"
	COL_END   = "\033[0m"
	PROMPT    = "(P)ASS, (F)AIL, (S)KIP: "

	PASS Status = 0
	FAIL Status = 1
	SKIP Status = 2
)

type TestCase struct {
	Name    string
	Arrange string
	Act     string
	Assert  string
}

type TestSuite struct {
	testcases []TestCase
	Name      string
}

type Status int

func WaitAnswer() Status {

	fmt.Printf(PROMPT)
	for {
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')

		switch string([]byte(input)[0]) {
		case "P", "p":
			return PASS
		case "F", "f":
			return FAIL
		case "S", "s":
			return SKIP
		default:
			fmt.Printf(PROMPT)
			continue
		}
	}
}

func SaveReport(filename string, suites []junit.JUnitTestsuite) error {

	var report junit.JUnitReport
	report.Suites = suites

	f, err := os.Create(filename)
	if err != nil {
		return err
	}

	defer f.Close()

	encoder := xml.NewEncoder(f)
	err = encoder.Encode(report)
	if err != nil {
		return err
	}
	fmt.Printf("Test report saved to %v\n", filename)

	return nil
}

func ReadGherkin(f *os.File) (TestSuite, error) {

	gherkinDocument, err := gherkin.ParseGherkinDocument(f)
	if err != nil {
		return TestSuite{}, err
	}
	feature := gherkinDocument.Feature

	suite := TestSuite{Name: feature.Name}
	for _, c := range feature.Children {
		var tc TestCase
		scenario := c.GetScenario()
		if len(scenario.Steps) != 0 {
			for _, s := range scenario.Steps {
				switch s.Keyword {
				case "Given ":
					tc.Arrange = s.Text
				case "Then ":
					tc.Act = s.Text
				case "When ":
					tc.Assert = s.Text
				default:
					fmt.Fprintf(os.Stdout, "Unknown: %s: %s\n", s.Keyword, s.Text)
				}
			}
		}
		tc.Name = scenario.Name
		suite.testcases = append(suite.testcases, tc)
	}

	return suite, nil
}

func ProcessTestcase(testcase TestCase) Status {

	fmt.Fprintf(os.Stdout, "Arrange: %+v\n", testcase.Arrange)
	fmt.Fprintf(os.Stdout, "Act: %+v\n", testcase.Act)
	fmt.Fprintf(os.Stdout, "Assert: %+v\n", testcase.Assert)

	return WaitAnswer()
}

func main() {

	flag.Usage = func() {
		fmt.Println("testicase is a tool for passing manual testcases.\n")
		fmt.Println("Usage:\n")
		flag.PrintDefaults()
	}
	var spec = flag.String("in", "", "spec filename")
	var tags = flag.String("tags", "", "filter by specified tags")
	var output = flag.String("out", "", "report filename")
	flag.Parse()

	if *tags != "" {
		fmt.Fprintf(os.Stdout, "Tags: ")
		for _, t := range strings.Split(*tags, " ") {
			fmt.Fprintf(os.Stdout, "%s ", t)
		}
		fmt.Fprintf(os.Stdout, "\n")
	}

	if *spec == "" {
		flag.Usage()
		os.Exit(1)
	}

	if _, err := os.Stat(*spec); os.IsNotExist(err) {
		fmt.Fprintf(os.Stdout, "%s\n", err)
		return
	}

	filename, _ := filepath.Abs(*spec)
	f, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stdout, "%s\n", err)
		return
	}

	var s TestSuite
	s, err = ReadGherkin(f)
	if err != nil {
		fmt.Fprintf(os.Stdout, "%s\n", err)
		return
	}

	suite := junit.JUnitTestsuite{Time: 0.0,
		Timestamp: time.Now().Format(time.RFC3339Nano),
		Name:      s.Name}
	suite.Hostname, _ = os.Hostname()
	if s.Name != "" {
		fmt.Fprintf(os.Stdout, "Feature name: %s%+v%s\n", COL_START, s.Name, COL_END)
	}
	for _, c := range s.testcases {
		fmt.Fprintf(os.Stdout, "Scenario name: %s\n", c.Name)
		testcase := junit.JUnitTestcase{Name: c.Name}
		switch ProcessTestcase(c) {
		case PASS:
		case FAIL:
			var s junit.JUnitFailure
			s.Value = "FAIL"
			testcase.Failure = &s
		case SKIP:
			testcase.Skipped = 1
		}
		/*
			start := time.Now()
			fmt.Fprintf(os.Stdout, "\nName: %+v\n", scenario.Name)
			testcase.Time = float64(time.Since(start) / time.Millisecond)
		*/
		suite.Time = suite.Time + testcase.Time
		suite.TestCases = append(suite.TestCases, testcase)
	}

	if *output != "" {
		var suites []junit.JUnitTestsuite
		suites = append(suites, suite)
		if SaveReport(*output, suites) != nil {
			fmt.Fprintf(os.Stdout, "%s\n", err)
			return
		}
	}
}
