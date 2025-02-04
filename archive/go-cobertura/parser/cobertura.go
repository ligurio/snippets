package cobertura

import (
	"encoding/xml"
	"io"
	"io/ioutil"
)

type Coverage struct {
	XMLName         xml.Name `xml:"coverage"`
	Name            string   `xml:"name,attr"`
	LinesValid      int      `xml:"lines-valid,attr,omitempty"`
	LinesCovered    int      `xml:"lines-covered,attr,omitempty"`
	LineRate        float64  `xml:"line-rate,attr,omitempty"`
	BranchesValid   int      `xml:"branches-valid,attr,omitempty"`
	BranchesCovered int      `xml:"branches-covered,attr,omitempty"`
	BranchRate      float64  `xml:"branch-rate,attr,omitempty"`
	Timestamp       int      `xml:"timstamp,attr,omitempty"`
	Complexity      float64  `xml:"complexity,attr,omitempty"`
	Version         float64  `xml:"version,attr,omitempty"`

	Sources  []Source  `xml:"source->source"`
	Packages []Package `xml:"package->package"`
}

type Source struct {
	XMLName xml.Name    `xml:"source"`
	Source  InnerResult `xml:"source,omitempty"`
}

type Package struct {
	XMLName    xml.Name `xml:"package"`
	Name       string   `xml:"name,attr,omitempty"`
	LineRate   float64  `xml:"line-rate,attr,omitempty"`
	BranchRate float64  `xml:"branch-rate,attr,omitempty"`
	Complexity float64  `xml:"complexity,attr,omitempty"`
	Classes    []Class  `xml:"class->class"`
}

type Class struct {
	XMLName    xml.Name `xml:"class"`
	Name       string   `xml:"name,attr,omitempty"`
	Filename   string   `xml:"filename,attr,omitempty"`
	LineRate   float64  `xml:"line-rate,attr,omitempty"`
	BranchRate float64  `xml:"branch-rate,attr,omitempty"`
	Complexity float64  `xml:"complexity,attr,omitempty"`
	Methods    []Method `xml:"methods->method"`
	Lines      []Line   `xml:"lines->line"`
}

type Line struct {
	XMLName           xml.Name    `xml:"line"`
	Number            int         `xml:"number,attr"`
	Hits              int         `xml:"hits,attr"`
	Branch            bool        `xml:"branch,attr"`
	ConditionCoverage string      `xml:"condition-coverage,attr"`
	Conditions        []Condition `xml:"conditions->condition"`
}

type Method struct {
	XMLName    xml.Name `xml:"method"`
	Name       string   `xml:"name,attr,omitempty"`
	Hits       int      `xml:"hits,attr,omitempty"`
	Signature  string   `xml:"signature,attr,omitempty"`
	BranchRate float64  `xml:"branch-rate,attr,omitempty"`
	LineRate   float64  `xml:"line-rate,attr,omitempty"`
	Lines      []Line   `xml:"lines->line"`
}

type Condition struct {
	XMLName xml.Name `xml:"condition"`

	Number   int    `xml:"number,attr,omitempty"`
	Type     string `xml:"type,attr,omitempty"`
	Coverage string `xml:"coverage,attr,omitempty"`
}

type InnerResult struct {
	Value string `xml:",innerxml"`
}

func NewParser(r io.Reader) (*Coverage, error) {

	var report = new(Coverage)

	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	err = xml.Unmarshal([]byte(buf), &report)
	if err != nil {
		return nil, err
	}

	return report, nil
}
