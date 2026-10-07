package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
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
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"payload.vbs"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("positional input accepted without -input: exit=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"stray", "-unknown:value"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("unknown option after positional was ignored: exit=%d stderr=%q", code, stderr.String())
	}
}

func TestCLIHelpExitsSuccessfully(t *testing.T) {
	for _, arg := range []string{"-h", "--help", "-?"} {
		t.Run(arg, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run([]string{"stray", arg}, &stdout, &stderr); code != 0 {
				t.Fatalf("help exit = %d, stderr=%q", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "-input") || !strings.Contains(stderr.String(), "-compression") {
				t.Fatalf("help output omits CLI options: %q", stderr.String())
			}
		})
	}
}

func TestCLIColonAttachedFlagsAndStrayPositionals(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "payload.vbs")
	if err := os.WriteFile(input, []byte(`WScript.Echo "hello"`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name       string
		outputFlag string
	}{
		{name: "short", outputFlag: "-o:"},
		{name: "long", outputFlag: "--output:"},
	} {
		t.Run(test.name, func(t *testing.T) {
			loader := filepath.Join(dir, test.name+".bin")
			module := filepath.Join(dir, test.name+".module")
			var stdout, stderr bytes.Buffer
			code := run([]string{
				"stray", "--input:" + input,
				"another-stray", test.outputFlag + loader,
				"-server:https://example.test:8443/modules/",
				"-modname:PAYLOAD", "-module-output:" + module,
				"-entropy:none", "-compression:none",
			}, &stdout, &stderr)
			if code != 0 || stderr.Len() != 0 {
				t.Fatalf("exit=%d stderr=%q", code, stderr.String())
			}
			for _, path := range []string{loader, module} {
				if data, err := os.ReadFile(path); err != nil || len(data) == 0 {
					t.Fatalf("output %q: bytes=%d err=%v", path, len(data), err)
				}
			}
			if !strings.Contains(stdout.String(), "https://example.test:8443/modules/PAYLOAD") {
				t.Fatalf("URL was altered: %q", stdout.String())
			}
		})
	}
}

func TestCLIBase64ClipboardIsBestEffortAndFormatScoped(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "payload.vbs")
	if err := os.WriteFile(input, []byte(`WScript.Echo "hello"`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name       string
		format     string
		wantCopies int
	}{
		{name: "base64", format: "base64", wantCopies: 1},
		{name: "binary", format: "bin", wantCopies: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := filepath.Join(dir, test.name+".out")
			var stdout, stderr bytes.Buffer
			var copied []byte
			copies := 0
			code := runWithClipboard([]string{
				"-input", input, "-format", test.format,
				"-compression", "none", "-output", output,
			}, &stdout, &stderr, func(data []byte) error {
				copies++
				copied = append([]byte(nil), data...)
				return errors.New("clipboard unavailable")
			})
			if code != 0 || stderr.Len() != 0 {
				t.Fatalf("exit=%d stderr=%q", code, stderr.String())
			}
			if copies != test.wantCopies {
				t.Fatalf("clipboard copies=%d, want %d", copies, test.wantCopies)
			}
			written, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(stdout.String(), "wrote "+output) {
				t.Fatalf("stdout=%q", stdout.String())
			}
			if !strings.Contains(stdout.String(), "Input        "+input) ||
				!strings.Contains(stdout.String(), "Output       "+output+" ("+test.format+")") ||
				!strings.Contains(stdout.String(), "Staging      Disabled") ||
				!strings.Contains(stdout.String(), "Compression  None") ||
				!strings.Contains(stdout.String(), "Instance     Embedded") ||
				!strings.Contains(stdout.String(), "Exit         Thread") ||
				!strings.Contains(stdout.String(), "Protections  ") {
				t.Fatalf("incomplete success report: %q", stdout.String())
			}
			if test.format == "base64" {
				if !bytes.Equal(copied, written) {
					t.Fatal("clipboard bytes differ from written Base64 output")
				}
				if _, err := base64.StdEncoding.DecodeString(string(written)); err != nil {
					t.Fatalf("written output is not Base64: %v", err)
				}
			}
		})
	}
	var stdout, stderr bytes.Buffer
	copies := 0
	if code := runWithClipboard([]string{
		"-input", input, "-format", "base64",
		"-compression", "none", "-output", dir,
	}, &stdout, &stderr, func([]byte) error {
		copies++
		return nil
	}); code != 1 || copies != 0 || !strings.Contains(stderr.String(), "write loader:") {
		t.Fatalf("failed write: exit=%d copies=%d stderr=%q", code, copies, stderr.String())
	}
}

func TestCLIStagedModuleDefaultsToCurrentDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	input := filepath.Join(dir, "payload.vbs")
	if err := os.WriteFile(input, []byte(`WScript.Echo "hello"`), 0o600); err != nil {
		t.Fatal(err)
	}
	loader := filepath.Join("output", "loader.bin")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"-input", input, "-output", loader, "-compression", "none",
		"-server", "https://example.test/modules/", "-modname", "PAYLOAD",
	}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Stat(loader); err != nil {
		t.Fatalf("loader output: %v", err)
	}
	module, err := os.ReadFile("PAYLOAD")
	if err != nil || len(module) == 0 {
		t.Fatalf("module in current directory: bytes=%d err=%v", len(module), err)
	}
	if _, err := os.Stat(filepath.Join("output", "PAYLOAD")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected module beside loader: %v", err)
	}
	if !strings.Contains(stdout.String(), "wrote staged module PAYLOAD") {
		t.Fatalf("stdout=%q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Staging      HTTPS (module PAYLOAD)") ||
		!strings.Contains(stdout.String(), "URL          https://example.test/modules/PAYLOAD") ||
		!strings.Contains(stdout.String(), "Instance     HTTP") {
		t.Fatalf("incomplete staged report: %q", stdout.String())
	}

	// An explicit module path still takes precedence over the cwd default.
	custom := filepath.Join("override", "module.bin")
	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"-input", input, "-output", loader, "-compression", "none",
		"-server", "https://example.test/modules/", "-modname", "CUSTOM",
		"-module-output", custom,
	}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("explicit module path: exit=%d stderr=%q", code, stderr.String())
	}
	if module, err := os.ReadFile(custom); err != nil || len(module) == 0 {
		t.Fatalf("explicit module output: bytes=%d err=%v", len(module), err)
	}
	if _, err := os.Stat("CUSTOM"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected module in cwd after override: %v", err)
	}

	blocked := filepath.Join(dir, "blocked")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	failedLoader := filepath.Join("failed", "loader.bin")
	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"-input", input, "-output", failedLoader, "-compression", "none",
		"-server", "https://example.test/modules/", "-modname", "FAIL",
		"-module-output", blocked,
	}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "write staged module:") {
		t.Fatalf("failed module write: exit=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Stat(failedLoader); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("loader exists after failed module write: %v", err)
	}
}

func TestCLIStagedSummaryReportsURLWithoutCredentials(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "payload.vbs")
	if err := os.WriteFile(input, []byte(`WScript.Echo "hello"`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"-input", input, "-output", filepath.Join(dir, "loader.bin"),
		"-module-output", filepath.Join(dir, "module.bin"),
		"-server", "https://operator:private@example.test/modules/",
		"-modname", "PAYLOAD", "-compression", "none",
	}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "URL          https://example.test/modules/PAYLOAD") ||
		strings.Contains(stdout.String(), "operator") || strings.Contains(stdout.String(), "private") {
		t.Fatalf("staged URL report exposes credentials or omits destination: %q", stdout.String())
	}
}

func TestCLIRejectsOutputThatOverwritesInput(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	input := "foo.vbs"
	source := []byte(`WScript.Echo "keep source"`)
	if err := os.WriteFile(input, source, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "loader", args: []string{"-output", input}},
		{name: "default staged module", args: []string{"-output", "loader.bin", "-server", "https://example.test/", "-modname", input}},
		{name: "explicit staged module", args: []string{"-output", "loader.bin", "-server", "https://example.test/", "-module-output", input}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append([]string{"-input", input, "-compression", "none"}, tc.args...)
			if code := run(args, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "output paths:") {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			got, err := os.ReadFile(input)
			if err != nil || !bytes.Equal(got, source) {
				t.Fatalf("source changed: %q, %v", got, err)
			}
			if _, err := os.Stat("loader.bin"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("loader exists after rejected output: %v", err)
			}
		})
	}
}

func TestValidateOutputTargetsRejectsAliases(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "source.vbs")
	loader := filepath.Join(dir, "Loader.bin")
	module := filepath.Join(dir, "module.bin")
	if err := os.WriteFile(input, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(loader, []byte("existing loader"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(loader, module); err != nil {
		t.Fatalf("create hard link: %v", err)
	}
	if err := validateOutputTargets(input, loader, module); err == nil {
		t.Fatal("hard-linked outputs accepted")
	}
	if err := os.Remove(module); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(loader, module); err == nil {
		if err := validateOutputTargets(input, loader, module); err == nil {
			t.Fatal("symlink output accepted")
		}
		if err := os.Remove(module); err != nil {
			t.Fatal(err)
		}
	}
	aliasDir := filepath.Join(dir, "alias")
	if err := os.Symlink(dir, aliasDir); err == nil {
		if err := validateOutputTargets(input, loader, filepath.Join(aliasDir, "Loader.bin")); err == nil {
			t.Fatal("parent-directory symlink alias accepted")
		}
	}
	if runtime.GOOS == "windows" {
		if err := validateOutputTargets(input, loader, filepath.Join(dir, "loader.BIN")); err == nil {
			t.Fatal("case-insensitive Windows output alias accepted")
		}
	}
}

func TestGenerationSummarySelectedOptions(t *testing.T) {
	var out bytes.Buffer
	printGenerationSummary(&out, "source.dll", "loader.uuid", "", "", churro.NativeDLL{}, nil,
		churro.FormatUUID, churro.EntropyDefault, churro.CompressionAPLib,
		churro.ExitProcess, churro.PEHeadersPreserve,
		&churro.HostImageContinuation{EntryPointRVA: 0x1a2b})
	for _, line := range []string{
		"Input        source.dll", "Type         Native DLL", "Function     DllMain",
		"Output       loader.uuid (uuid)",
		"Compression  aPLib", "Exit         Process", "OEP          0x1A2B",
		"ARX encryption", "PE headers preserve",
	} {
		if !strings.Contains(out.String(), line) {
			t.Fatalf("summary missing %q: %q", line, out.String())
		}
	}
	out.Reset()
	staging := &churro.HTTPStaging{}
	staging.BaseURL.Scheme = "https"
	printGenerationSummary(&out, "source.vbs", "loader.bin", "PAYLOAD", "https://example.test/modules/PAYLOAD", churro.VBScript{}, staging,
		churro.FormatBinary, churro.EntropyNone, churro.CompressionNone,
		churro.ExitBlock, churro.PEHeadersOverwrite, nil)
	for _, line := range []string{"Staging      HTTPS (module PAYLOAD)", "Compression  None", "Exit         Block"} {
		if !strings.Contains(out.String(), line) {
			t.Fatalf("summary missing %q: %q", line, out.String())
		}
	}
	if strings.Contains(out.String(), "ARX encryption") || strings.Contains(out.String(), "PE headers") {
		t.Fatalf("summary reported inapplicable protection: %q", out.String())
	}
	out.Reset()
	managed := churro.DotNetDLL{
		EntryPoint: churro.DotNetStaticMethod{TypeName: "Fixture.Entry", MethodName: "Run"},
		Runtime:    churro.DotNetRuntime{AppDomain: "FixtureDomain"},
	}
	printGenerationSummary(&out, "source.dll", "loader.bin", "", "", managed, nil,
		churro.FormatBinary, churro.EntropyDefault, churro.CompressionNone,
		churro.ExitThread, churro.PEHeadersOverwrite, nil)
	for _, line := range []string{
		"Type         Managed DLL", "Class        Fixture.Entry",
		"Method       Run", "Domain       FixtureDomain",
	} {
		if !strings.Contains(out.String(), line) {
			t.Fatalf("managed summary missing %q: %q", line, out.String())
		}
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

func TestManagedArgumentFlagsMapToTypedPayload(t *testing.T) {
	args := `one "two words"`
	exe, err := payloadForPath("payload.exe", cliSyntheticManagedPE(false), payloadOptions{arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	managedEXE, ok := exe.(churro.DotNetExecutable)
	if !ok || managedEXE.Arguments != args {
		t.Fatalf("managed EXE payload = %#v", exe)
	}
	dll, err := payloadForPath("payload.dll", cliSyntheticManagedPE(true), payloadOptions{
		class: "Example.Entry", method: "Run", arguments: args,
	})
	if err != nil {
		t.Fatal(err)
	}
	managedDLL, ok := dll.(churro.DotNetDLL)
	if !ok || managedDLL.EntryPoint.Arguments != args || managedDLL.EntryPoint.TypeName != "Example.Entry" || managedDLL.EntryPoint.MethodName != "Run" {
		t.Fatalf("managed DLL payload = %#v", dll)
	}
	if _, err := payloadForPath("payload.dll", cliSyntheticManagedPE(true), payloadOptions{
		class: "Example.Entry", method: "Run", arguments: args, unicode: true,
	}); err == nil {
		t.Fatal("managed DLL accepted native Unicode export flag")
	}
}

func TestPEPayloadTypeUsesHeaderWithRenamedFile(t *testing.T) {
	for _, test := range []struct {
		name    string
		path    string
		image   []byte
		options payloadOptions
		want    string
	}{
		{name: "native DLL named exe", path: "payload.exe", image: cliSyntheticPE(true), options: payloadOptions{method: "Run"}, want: "native DLL"},
		{name: "native EXE named dll", path: "payload.dll", image: cliSyntheticPE(false), options: payloadOptions{thread: true}, want: "native EXE"},
		{name: "managed DLL named exe", path: "payload.exe", image: cliSyntheticManagedPE(true), options: payloadOptions{class: "Example.Entry", method: "Run"}, want: "managed DLL"},
		{name: "managed EXE named dll", path: "payload.dll", image: cliSyntheticManagedPE(false), want: "managed EXE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload, err := payloadForPath(test.path, test.image, test.options)
			if err != nil {
				t.Fatal(err)
			}
			got := "unknown"
			switch payload.(type) {
			case churro.NativeDLL:
				got = "native DLL"
			case churro.NativeExecutable:
				got = "native EXE"
			case churro.DotNetDLL:
				got = "managed DLL"
			case churro.DotNetExecutable:
				got = "managed EXE"
			}
			if got != test.want {
				t.Fatalf("payload type = %s, want %s", got, test.want)
			}
		})
	}
}

func cliSyntheticManagedPE(dll bool) []byte {
	image := cliSyntheticPE(dll)
	fh := image[0x84:]
	binary.LittleEndian.PutUint16(fh[0:], 0x14c)
	binary.LittleEndian.PutUint16(fh[16:], 224)
	opt := image[0x98:]
	binary.LittleEndian.PutUint16(opt, 0x10b)
	binary.LittleEndian.PutUint32(opt[92:], 16)
	binary.LittleEndian.PutUint32(opt[96+14*8:], 0x1000)
	copy(image[0x178:0x178+40], image[0x188:0x188+40])
	return image
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
