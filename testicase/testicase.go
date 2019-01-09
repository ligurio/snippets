package main

import (
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

const (
	COL_START = "\033[32m"
	COL_END   = "\033[0m"
)

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
	r, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stdout, "%s\n", err)
		return
	}

	gherkinDocument, err := gherkin.ParseGherkinDocument(r)
	if err != nil {
		fmt.Fprintf(os.Stdout, "%s\n", err)
		return
	}

	feature := gherkinDocument.Feature
	fmt.Fprintf(os.Stdout, "Feature name: %s%+v%s\n", COL_START, feature.Name, COL_END)

	var suite junit.JUnitTestsuite
	suite.Hostname, _ = os.Hostname()
	suite.Timestamp = time.Now().Format(time.RFC3339Nano)
	suite.Name = feature.Name
	suite.Time = 0.0
	for _, c := range feature.Children {
		var testcase junit.JUnitTestcase
		start := time.Now()
		scenario := c.GetScenario()
		fmt.Fprintf(os.Stdout, "\nName: %+v\n", scenario.Name)
		if len(scenario.Steps) != 0 {
			for _, s := range scenario.Steps {
				fmt.Fprintf(os.Stdout, "%s: %s\n", s.Keyword, s.Text)
			}
		}
		testcase.Name = scenario.Name
		/* time.Sleep(1000 * time.Millisecond) */
		testcase.Time = float64(time.Since(start) / time.Millisecond)
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
