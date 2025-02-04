package main

import (
	. "github.com/ligurio/go-cobertura/parser"
	"os"
	"testing"
)

type tcase struct {
	name string
	skip bool
}

var testset = []tcase{
	{
		name: "example.xml",
		skip: false,
	},
}

func TestParser(t *testing.T) {
	for _, tcase := range testset {
		if tcase.skip {
			t.Logf("Skip: %s", tcase.name)
			continue
		}
		t.Logf("Running: %s", tcase.name)

		file, err := os.Open("tests/" + tcase.name)
		if err != nil {
			t.Fatal(err)
		}

		report, err := NewParser(file)
		if err != nil {
			t.Fatalf("error parsing %s: %s", tcase.name, err)
		}

		if report == nil {
			t.Fatalf("Report == nil")
		}
	}
}
