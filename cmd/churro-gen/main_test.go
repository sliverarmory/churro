package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sliverarmory/churro"
)

func TestParseFormat(t *testing.T) {
	cases := []struct {
		input string
		want  churro.Format
	}{
		{"bin", churro.FormatBinary},
		{"BINARY", churro.FormatBinary},
		{"base64", churro.FormatBase64},
		{"c", churro.FormatC},
		{"ruby", churro.FormatRuby},
		{"python", churro.FormatPython},
		{"powershell", churro.FormatPowerShell},
		{"csharp", churro.FormatCSharp},
		{"hex", churro.FormatHex},
		{"uuid", churro.FormatUUID},
	}
	for _, test := range cases {
		got, err := parseFormat(test.input)
		if err != nil || got != test.want {
			t.Errorf("parseFormat(%q) = %d, %v; want %d", test.input, got, err, test.want)
		}
	}
	if _, err := parseFormat("wat"); err == nil {
		t.Fatal("unknown format accepted")
	}
}

func TestScriptPayloadAndInvocationBoundary(t *testing.T) {
	source := []byte("WScript.Echo \"hello\"")
	payload, err := payloadForPath("test.VBS", source, payloadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	script, ok := payload.(churro.VBScript)
	if !ok || !bytes.Equal(script.Source, source) {
		t.Fatalf("script payload = %#v", payload)
	}
	_, err = payloadForPath("test.vbs", source, payloadOptions{method: "Run"})
	if err == nil || !strings.Contains(err.Error(), "invocation flags") {
		t.Fatalf("script accepted DLL invocation flags: %v", err)
	}
}

func TestCLIArgumentErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("missing input: exit=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"-version"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "churro-gen") {
		t.Fatalf("version: exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestStagingForFlags(t *testing.T) {
	if _, err := stagingForFlags("", "PAYLOAD", ""); err == nil {
		t.Fatal("module name accepted without a server")
	}
	if _, err := stagingForFlags("", "", "module.bin"); err == nil {
		t.Fatal("module output accepted without a server")
	}
	staging, err := stagingForFlags("https://example.test/objects/", "PAYLOAD", "module.bin")
	if err != nil {
		t.Fatal(err)
	}
	if staging.ModuleName != "PAYLOAD" || staging.BaseURL.String() != "https://example.test/objects/" {
		t.Fatalf("staging = %#v", staging)
	}
}
