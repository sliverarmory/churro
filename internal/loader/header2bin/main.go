// Command header2bin extracts exe2h's byte array into an embedded loader blob.
package main

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"
)

var byteLiteral = regexp.MustCompile(`0x[[:xdigit:]]{2}`)

func main() {
	if len(os.Args) != 3 {
		fatalf("usage: header2bin input.h output.bin")
	}
	source, err := os.ReadFile(os.Args[1])
	if err != nil {
		fatalf("read header: %v", err)
	}
	begin := bytes.IndexByte(source, '{')
	end := bytes.LastIndexByte(source, '}')
	if begin < 0 || end <= begin {
		fatalf("header has no byte array")
	}
	literals := byteLiteral.FindAll(source[begin+1:end], -1)
	if len(literals) == 0 {
		fatalf("header byte array is empty")
	}
	output := make([]byte, len(literals))
	for i, literal := range literals {
		value, err := strconv.ParseUint(string(literal[2:]), 16, 8)
		if err != nil {
			fatalf("parse byte %d: %v", i, err)
		}
		output[i] = byte(value)
	}
	if err := os.WriteFile(os.Args[2], output, 0o644); err != nil {
		fatalf("write blob: %v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
