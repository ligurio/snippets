package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ligurio/go-cobertura/parser"
)

func main() {

	var f = flag.String("file", "", "filename")
	flag.Parse()

	file, err := os.Open(*f)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	report, err := cobertura.NewParser(file)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("%+v\n", report)
	}
}
