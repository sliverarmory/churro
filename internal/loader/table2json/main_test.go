package main

import (
	"strings"
	"testing"
)

const functionHeader = `#define LOADER_FN_COUNT 2
static const fn_meta_t LOADER_FNS[LOADER_FN_COUNT] = {
  { 0x00000000, 0x00001234, 0, {0,0,0}, ".text" },
  { 0x00001234, 0x00000040, 1, {0,0,0}, ".cipher" },
};
`

const referenceHeader = `#define LOADER_REF_COUNT 1
static const ref_t LOADER_REFS[LOADER_REF_COUNT + 1] = {
  { 0x0000002a, 5, 1, 0, 1 },
  { 0, 0, 0, 0, 0 }
};
`

func TestParseTables(t *testing.T) {
	got, err := parseTables([]byte(functionHeader), []byte(referenceHeader))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Functions) != 2 || got.Functions[1].Name != ".cipher" ||
		got.Functions[1].Offset != 0x1234 || !got.Functions[1].SinglePage {
		t.Fatalf("unexpected function table: %+v", got.Functions)
	}
	if len(got.References) != 1 || got.References[0].TargetFunction != 1 ||
		got.References[0].DisplacementOffset != 1 {
		t.Fatalf("unexpected reference table: %+v", got.References)
	}
}

func TestParseTablesRejectsMalformedMetadata(t *testing.T) {
	cases := []struct {
		name string
		fn   string
		ref  string
	}{
		{"missing function", strings.Replace(functionHeader, "_FN_COUNT 2", "_FN_COUNT 3", 1), referenceHeader},
		{"missing reference", functionHeader, strings.Replace(referenceHeader, "_REF_COUNT 1", "_REF_COUNT 2", 1)},
		{"invalid index", functionHeader, strings.Replace(referenceHeader, "5, 1, 0, 1", "5, 1, 0, 2", 1)},
		{"invalid sentinel", functionHeader, strings.Replace(referenceHeader, "{ 0, 0, 0, 0, 0 }", "{ 1, 0, 0, 0, 0 }", 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseTables([]byte(tc.fn), []byte(tc.ref)); err == nil {
				t.Fatal("expected malformed metadata to be rejected")
			}
		})
	}
}
