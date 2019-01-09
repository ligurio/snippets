package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"gopkg.in/yaml.v2"
)

const (
	SHORTDESC = 80 // Number of symbols to add from testcase step to description
	URL       = "http://localhost:8080/upload"
)

// A TAP-Directive (TODO/SKIP)
type Directive int

const (
	None Directive = iota // No directive given
	Todo                  // Testpoint is a TODO
	Skip                  // Testpoint was skipped
)

func (d Directive) String() string {
	switch d {
	case None:
		return "None"
	case Todo:
		return "TODO"
	case Skip:
		return "SKIP"
	}
	return ""
}

// A single TAP-Testline
type Testline struct {
	Ok          bool      // Whether the Testpoint executed ok
	Num         uint      // The number of the test
	Description string    // A short description
	Directive   Directive // Whether the test was skipped or is a todo
	Explanation string    // A short explanation why the test was skipped/is a todo
	Diagnostic  string    // A more detailed diagnostic message about the failed test
	Yaml        []byte    // The inline Yaml-document, if given
}

// The outcome of a Testsuite
type Testsuite struct {
	Ok    bool        // Whether the Testsuite as a whole succeded
	Tests []*Testline // Description of all Testlines
	Plan  int         // Number of tests intended to run
}

type Testcase struct {
	Name         string
	Summary      string
	Precondition string
	Steps        []Step
}

type Step struct {
	Step  string
	Check string
}

func CreateReport(s *Testsuite, w io.Writer) error {

	bytes := []byte("")
	bytes = append(bytes, "TAP version 13\n"...)
	version := "1.." + strconv.Itoa(int(s.Plan)) + "\n"
	bytes = append(bytes, version...)

	var tline string

	for _, t := range s.Tests {
		if t.Ok {
			tline = "ok" + " " + strconv.Itoa(int(t.Num)) + " - " + t.Description
		} else {
			tline = "not ok" + " " + strconv.Itoa(int(t.Num)) + " - " + t.Description
		}

		tline = tline + " # "

		t.Directive = 2
		fmt.Printf("%s", t.Directive)
		tline = tline + string(t.Directive)
/*
		if t.Directive != 0 {
			tline = tline + string(t.Directive)
		}
*/

		if t.Explanation != "" {
			sz := len(t.Explanation)
			if sz > 0 && t.Explanation[sz-1] == '\n' {
				t.Explanation = t.Explanation[:sz-1]
			}
			tline = tline + " " + t.Explanation
		}

		if t.Diagnostic != "" {
			tline = tline + " " + t.Diagnostic
		}

		bytes = append(bytes, tline...)
		bytes = append(bytes, "\n"...)
		if t.Yaml != nil {
			bytes = append(bytes, t.Yaml...)
			bytes = append(bytes, "\n"...)
		}
	}

	writer := bufio.NewWriter(w)

	writer.Write(bytes)
	writer.WriteByte('\n')
	writer.Flush()

	return nil
}

func SaveReport(filename string, s *Testsuite) error {

	f, err := os.Create(filename)
	if err != nil {
		fmt.Println(err)
	}

	defer f.Close()

	err = CreateReport(s, f)
	if err != nil {
		fmt.Printf("Failed to write report: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Report saved to the file %v.\n", filename)

	return nil
}

func SendReport(filename string, targetUrl string) error {
	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	fileWriter, err := bodyWriter.CreateFormFile("uploadfile", filename)
	if err != nil {
		fmt.Println("error writing to buffer")
		return err
	}

	fh, err := os.Open(filename)
	if err != nil {
		fmt.Println("error opening file")
		return err
	}

	_, err = io.Copy(fileWriter, fh)
	if err != nil {
		return err
	}

	contentType := bodyWriter.FormDataContentType()
	bodyWriter.Close()

	resp, err := http.Post(targetUrl, contentType, bodyBuf)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	resp_body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fmt.Println(resp.Status)
	fmt.Println(string(resp_body))
	return nil
}

func main() {

	flag.Usage = func() {
		fmt.Println("testicase is a tool for passing manual testcases.\n")
		fmt.Println("Usage:\n")
		flag.PrintDefaults()
	}

	var fileTcase = flag.String("file", "", "testcase filename")

	flag.Parse()

	if *fileTcase == "" {
		flag.Usage()
		os.Exit(1)
	}

	var suite Testsuite

	if _, err := os.Stat(*fileTcase); os.IsNotExist(err) {
		fmt.Printf("File %v doesn't exist.\n", *fileTcase)
		os.Exit(1)
	}

	tc := Testcase{}

	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigs
		fmt.Println()
		fmt.Println(sig)
		done <- true
		os.Exit(1)
	}()

	filename, _ := filepath.Abs(*fileTcase)
	yamlFile, err := ioutil.ReadFile(filename)

	if err != nil {
		panic(err)
	}

	err = yaml.Unmarshal(yamlFile, &tc)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	if *fileTcase != "" {
		fmt.Printf("Filename: %v\n", filepath.Base(*fileTcase))
	}
	if string(tc.Name) != "" {
		fmt.Printf("Testcase name: %v\n", string(tc.Name))
	}
	if string(tc.Summary) != "" {
		fmt.Printf("Summary: %v\n", string(tc.Summary))
	}
	if string(tc.Precondition) != "" {
		fmt.Printf("Precondition: %v\n", string(tc.Precondition))
	}

	fmt.Printf("\n\033[32m ~ Testcases will follow. \033[0m\n")
	fmt.Printf("\033[32m ~ Possible answers: [Yy] is PASS, [Ss] is SKIP, [Nn] or everything else will be treated as FAIL. \033[0m\n\n")

	suite.Plan = 0
	suite.Ok = true

	for _, s := range tc.Steps {
		fmt.Printf("\n[%d/%d]\n", suite.Plan+1, len(tc.Steps))
		fmt.Printf("\033[31m *** \033[0m %v\n", s.Step)
		fmt.Printf("\033[31m *** \033[0m %v\n", s.Check)
		fmt.Printf("Result? ")

		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')

		t := new(Testline)

		if len([]byte(input)) == 2 {
			switch string([]byte(input)[0]) {
			case "Y", "y":
				t.Ok = true
			case "N", "n":
				t.Ok = false
				suite.Ok = false
			case "S", "s":
				t.Ok = false
				t.Directive = Skip
			default:
				t.Ok = false
				suite.Ok = false
				t.Explanation = string([]byte(input))
			}
		} else {
			t.Ok = false
			suite.Ok = false
			t.Explanation = string([]byte(input))
		}

		if len(s.Step) <= SHORTDESC {
			t.Description = s.Step
		} else {
			t.Description = s.Step[0:SHORTDESC]
		}

		suite.Plan++
		t.Num = uint(suite.Plan)
		suite.Tests = append(suite.Tests, t)
	}

	fmt.Printf("\n\033[32m ~ Testcase finished. \033[0m\n")
	fmt.Printf("\033[32m ~ Press <Enter> to upload, <Ctrl-C> to cancel. \033[0m\n")

	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')

	if string([]byte(input)) == "\n" {
		var reportName = "report-" + string(time.Now().Format("20060102-15-04-05")) + ".tap"

		err = SaveReport(reportName, &suite)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		err := SendReport(reportName, URL)
		if err != nil {
			log.Fatalf("error: %v", err)
		}
	}
}
