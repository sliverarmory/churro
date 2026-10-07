package churro

import (
	"context"
	"encoding/binary"
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestGeneratorClosedError(t *testing.T) {
	generator := NewGenerator()
	if err := generator.Close(); err != nil {
		t.Fatal(err)
	}
	if err := generator.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	_, err := generator.Generate(context.Background(), Request{})
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("Generate after Close = %v, want ErrClosed", err)
	}
}

func TestGenerateRequestValidationError(t *testing.T) {
	_, err := Generate(context.Background(), Request{})
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("empty request error = %v, want *ValidationError", err)
	}
	if validation.Field != "payload" {
		t.Fatalf("validation field = %q, want payload", validation.Field)
	}
	var generation *GenerationError
	if !errors.As(err, &generation) || generation.Code != ErrorFileEmpty {
		t.Fatalf("empty request code = %v, want ErrorFileEmpty", err)
	}
}

func TestStagingValidationErrorCodes(t *testing.T) {
	payload := JScript{Source: []byte("WScript.Echo(1)")}
	tests := []struct {
		name string
		url  string
		mod  string
		code ErrorCode
	}{
		{"invalid scheme", "ftp://example.test/", "PAYLOAD", ErrorInvalidURL},
		{"URL too long", "https://example.test/" + strings.Repeat("a", 240), "PAYLOAD", ErrorURLTooLong},
		{"invalid module name", "https://example.test/", "../bad", ErrorInvalidURL},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base, parseErr := url.Parse(test.url)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			_, err := Generate(context.Background(), Request{
				Payload: payload, Staging: &HTTPStaging{BaseURL: *base, ModuleName: test.mod},
			})
			var generation *GenerationError
			var validation *ValidationError
			if !errors.As(err, &generation) || generation.Code != test.code || !errors.As(err, &validation) {
				t.Fatalf("staging error = %v, want code %d and ValidationError", err, test.code)
			}
		})
	}
}

func TestGeneratorContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("New with canceled context = %v", err)
	}
	if _, err := NewGenerator().Generate(ctx, Request{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Generate with canceled context = %v", err)
	}
}

func TestNativeArgumentsValidation(t *testing.T) {
	request := Request{Payload: NativeExecutable{Image: []byte{1}, Arguments: "one two"}}
	n, err := normalizeGeneration(request)
	if err != nil || n.args != "one two" {
		t.Fatalf("native EXE arguments = %q, %v", n.args, err)
	}
	request.Payload = NativeDLL{Image: []byte{1}, Export: &NativeDLLExport{
		Name: "RunW", Arguments: "hello", Unicode: true,
	}}
	n, err = normalizeGeneration(request)
	if err != nil || n.args != "hello" || !n.unicode {
		t.Fatalf("native DLL argument = %q unicode=%v err=%v", n.args, n.unicode, err)
	}
	request.Payload = NativeExecutable{Image: []byte{1}, Arguments: strings.Repeat("A", maxArgumentsBytes+1)}
	if _, err := normalizeGeneration(request); err == nil {
		t.Fatal("oversize target arguments accepted")
	}
	request.Payload = NativeExecutable{Image: []byte{1}, Arguments: "A\x00B"}
	if _, err := normalizeGeneration(request); err == nil {
		t.Fatal("NUL in target arguments accepted")
	}
}

func TestGenerationErrorCodesFromPEInput(t *testing.T) {
	tests := []struct {
		name    string
		payload Payload
		code    ErrorCode
	}{
		{"invalid PE", NativeExecutable{Image: []byte("MZ")}, ErrorFileInvalid},
		{"missing DLL export", NativeDLL{
			Image:  syntheticNativePEForAPI(true, "Run"),
			Export: &NativeDLLExport{Name: "Missing"},
		}, ErrorDLLExport},
		{"type mismatch", NativeExecutable{Image: syntheticNativePEForAPI(true, "")}, ErrorPayloadTypeMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Generate(context.Background(), Request{Payload: test.payload})
			var generation *GenerationError
			if !errors.As(err, &generation) || generation.Code != test.code || errors.Unwrap(generation) == nil {
				t.Fatalf("Generate() error = %v, want code %d with cause", err, test.code)
			}
		})
	}
	x86 := syntheticNativePEForAPI(false, "")
	binary.LittleEndian.PutUint16(x86[0x84:], 0x14c)
	_, err := Generate(context.Background(), Request{Payload: NativeExecutable{Image: x86}})
	var generation *GenerationError
	if !errors.As(err, &generation) || generation.Code != ErrorArchitectureMismatch {
		t.Fatalf("x86 Generate() = %v, want architecture mismatch", err)
	}
}

func syntheticNativePEForAPI(dll bool, export string) []byte {
	image := make([]byte, 0x600)
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
	if export != "" {
		binary.LittleEndian.PutUint32(opt[112:], 0x1000)
	}
	sec := image[0x188:]
	copy(sec, ".rdata")
	binary.LittleEndian.PutUint32(sec[8:], 0x400)
	binary.LittleEndian.PutUint32(sec[12:], 0x1000)
	binary.LittleEndian.PutUint32(sec[16:], 0x400)
	binary.LittleEndian.PutUint32(sec[20:], 0x200)
	if export != "" {
		binary.LittleEndian.PutUint32(image[0x200+24:], 1)
		binary.LittleEndian.PutUint32(image[0x200+32:], 0x1050)
		binary.LittleEndian.PutUint32(image[0x250:], 0x1060)
		copy(image[0x260:], export+"\x00")
	}
	return image
}

func TestCustomLoaderBundleOwnsInputs(t *testing.T) {
	bundle := EmbeddedLoaderBundle()
	generator, err := NewWithLoader(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	first := generator.bundle.PEB1[0]
	bundle.PEB1[0] ^= 0xff
	if generator.bundle.PEB1[0] != first {
		t.Fatal("custom loader bundle retained caller-owned image")
	}
	result, err := generator.Generate(context.Background(), Request{
		Payload: JScript{Source: []byte("WScript.Echo(1)")},
	})
	if err != nil || len(result.Loader) == 0 {
		t.Fatalf("generate with custom bundle: size=%d err=%v", len(result.Loader), err)
	}
	if err := generator.Close(); err != nil {
		t.Fatal(err)
	}
	bundle = EmbeddedLoaderBundle()
	bundle.PEB1Meta.Functions[0].Size++
	if _, err := NewWithLoader(context.Background(), bundle); err == nil {
		t.Fatal("out-of-bounds loader function accepted")
	}
}
