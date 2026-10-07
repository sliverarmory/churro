package main

import (
	"bytes"
	"encoding/binary"
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
		{"2", churro.FormatBase64},
		{"c", churro.FormatC},
		{"ruby", churro.FormatRuby},
		{"rb", churro.FormatRuby},
		{"python", churro.FormatPython},
		{"powershell", churro.FormatPowerShell},
		{"ps", churro.FormatPowerShell},
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

func TestLegacyOptionValuesAndDefaults(t *testing.T) {
	if got := defaultOutputForFormat(churro.FormatC); got != "loader.c" {
		t.Fatalf("C default output = %q", got)
	}
	if got := defaultOutputForFormat(churro.FormatUUID); got != "loader.uuid" {
		t.Fatalf("UUID default output = %q", got)
	}
	if got, err := parseExit("2"); err != nil || got != churro.ExitProcess {
		t.Fatalf("legacy exit = %v, %v", got, err)
	}
	if got, err := parseEntropy("low"); err != nil || got != churro.EntropyNames {
		t.Fatalf("legacy entropy = %v, %v", got, err)
	}
	if got, err := parseHeaders("2"); err != nil || got != churro.PEHeadersPreserve {
		t.Fatalf("legacy headers = %v, %v", got, err)
	}
	if got, err := parseCompression("aplib"); err != nil || got != churro.CompressionAPLib {
		t.Fatalf("compression = %v, %v", got, err)
	}
	continuation, err := parseContinuation("0x1a2b")
	if err != nil || continuation == nil || continuation.EntryPointRVA != 0x1a2b {
		t.Fatalf("hex continuation = %#v, %v", continuation, err)
	}
	if _, err := parseContinuation("not-hex"); err == nil {
		t.Fatal("invalid host continuation accepted")
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
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"-i", "missing.exe", "-g", "2"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "deprecated") {
		t.Fatalf("invalid legacy chunked option: exit=%d stderr=%q", code, stderr.String())
	}
}

func TestCLIHelpExitsSuccessfully(t *testing.T) {
	for _, arg := range []string{"-h", "--help"} {
		t.Run(arg, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run([]string{arg}, &stdout, &stderr); code != 0 {
				t.Fatalf("help exit = %d, stderr=%q", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "-input") || !strings.Contains(stderr.String(), "-compression") {
				t.Fatalf("help output omits CLI options: %q", stderr.String())
			}
		})
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

func TestNativeArgumentFlagsMapToTypedPayload(t *testing.T) {
	exe, err := payloadForPath("payload.exe", cliSyntheticPE(false), payloadOptions{arguments: `one "two words"`})
	if err != nil {
		t.Fatal(err)
	}
	nativeEXE, ok := exe.(churro.NativeExecutable)
	if !ok || nativeEXE.Arguments != `one "two words"` {
		t.Fatalf("native EXE payload = %#v", exe)
	}
	dll, err := payloadForPath("payload.dll", cliSyntheticPE(true), payloadOptions{
		method: "RunW", arguments: "hello", unicode: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	nativeDLL, ok := dll.(churro.NativeDLL)
	if !ok || nativeDLL.Export == nil || nativeDLL.Export.Arguments != "hello" || !nativeDLL.Export.Unicode {
		t.Fatalf("native DLL payload = %#v", dll)
	}
	if _, err := payloadForPath("payload.dll", cliSyntheticPE(true), payloadOptions{arguments: "hello"}); err == nil {
		t.Fatal("DLL argument without export accepted")
	}
}

func cliSyntheticPE(dll bool) []byte {
	image := make([]byte, 0x400)
	copy(image, "MZ")
	binary.LittleEndian.PutUint32(image[0x3c:], 0x80)
	copy(image[0x80:], "PE\x00\x00")
	fh := image[0x84:]
	binary.LittleEndian.PutUint16(fh[0:], 0x8664)
	binary.LittleEndian.PutUint16(fh[2:], 1)
	binary.LittleEndian.PutUint16(fh[16:], 240)
	if dll {
		binary.LittleEndian.PutUint16(fh[18:], 0x2000)
	}
	opt := image[0x98:]
	binary.LittleEndian.PutUint16(opt, 0x20b)
	binary.LittleEndian.PutUint32(opt[60:], 0x200)
	binary.LittleEndian.PutUint32(opt[108:], 16)
	sec := image[0x188:]
	copy(sec, ".rdata")
	binary.LittleEndian.PutUint32(sec[8:], 0x200)
	binary.LittleEndian.PutUint32(sec[12:], 0x1000)
	binary.LittleEndian.PutUint32(sec[16:], 0x200)
	binary.LittleEndian.PutUint32(sec[20:], 0x200)
	return image
}
