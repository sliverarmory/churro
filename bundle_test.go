package churro

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"
)

// These checks exercise metadata validation only. Executable N>1 loader
// behavior is covered by the native-loader integration tests.
func TestMultiSectionBundleMetadataValidation(t *testing.T) {
	bundle := EmbeddedLoaderBundle()
	bundle.PEB1 = append([]byte(nil), bundle.PEB1...)
	bundle.PEB1[1000] = 0xe8
	binary.LittleEndian.PutUint32(bundle.PEB1[1001:1005], 4096-(1000+5))
	bundle.PEB1Meta = LoaderMetadata{
		Functions: []LoaderFunction{
			{Offset: 0, Size: 4096, SinglePage: true, Name: ".text"},
			{Offset: 4096, Size: uint32(len(bundle.PEB1) - 4096), Name: ".next"},
		},
		References: []LoaderReference{{
			SrcBlobOff: 1000, InstLength: 5, DispOffset: 1, SrcFn: 0, TargetFn: 1,
		}},
	}
	if _, err := NewWithLoader(context.Background(), bundle); err != nil {
		t.Fatalf("valid multi-section metadata rejected: %v", err)
	}
	bundle.PEB1[1000] = 0xe9
	if _, err := NewWithLoader(context.Background(), bundle); err == nil || !strings.Contains(err.Error(), "not CALL rel32") {
		t.Fatalf("non-call protected reference = %v", err)
	}
	bundle.PEB1[1000] = 0xe8
	bundle.PEB1Meta.References[0].TargetFn = 2
	if _, err := NewWithLoader(context.Background(), bundle); err == nil || !strings.Contains(err.Error(), "function index") {
		t.Fatalf("out-of-range function reference = %v", err)
	}
	bundle.PEB1Meta.References[0].TargetFn = 1
	bundle.PEB1Meta.References[0].DispOffset = 3
	if _, err := NewWithLoader(context.Background(), bundle); err == nil || !strings.Contains(err.Error(), "instruction bounds") {
		t.Fatalf("out-of-range displacement = %v", err)
	}
	bundle.PEB1Meta.References[0].DispOffset = 1
	bundle.PEB1Meta.Functions[1].Offset = 4095
	if _, err := NewWithLoader(context.Background(), bundle); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("overlapping function sections = %v", err)
	}
}

func TestEmbeddedLoaderBundleMetadata(t *testing.T) {
	bundle := EmbeddedLoaderBundle()
	if got := len(bundle.PEB1Meta.Functions); got != 6 {
		t.Fatalf("PEB1 function count = %d, want 6", got)
	}
	if got := len(bundle.PEB2Meta.References); got != 39 {
		t.Fatalf("PEB2 reference count = %d, want 39", got)
	}
	if err := bundle.validate(); err != nil {
		t.Fatalf("embedded bundle validation: %v", err)
	}
	bundle.PEB1Meta.Functions[0].Name = "changed"
	if got := EmbeddedLoaderBundle().PEB1Meta.Functions[0].Name; got != ".text" {
		t.Fatalf("embedded metadata was mutated: %q", got)
	}
}

func TestMultiSectionBundleDispatchCapacity(t *testing.T) {
	bundle := EmbeddedLoaderBundle()
	bundle.PEB1Meta = LoaderMetadata{Functions: make([]LoaderFunction, 16)}
	for i := range bundle.PEB1Meta.Functions {
		bundle.PEB1Meta.Functions[i] = LoaderFunction{
			Offset: uint32(i * 100), Size: 100, Name: ".section",
		}
	}
	bundle.PEB1Meta.Functions[0].Name = ".text"
	if _, err := NewWithLoader(context.Background(), bundle); err == nil || !strings.Contains(err.Error(), "dispatch table capacity") {
		t.Fatalf("16-section bundle accepted: %v", err)
	}
}

func TestCustomAPIImportCapacityAndValidation(t *testing.T) {
	bundle := EmbeddedLoaderBundle()
	bundle.APIImports = append(bundle.APIImports, APIImport{Module: "advapi32.dll", Name: "GetUserNameA"})
	if _, err := NewWithLoader(context.Background(), bundle); err != nil {
		t.Fatalf("62-import bundle rejected: %v", err)
	}
	bundle.APIImports = append(bundle.APIImports,
		APIImport{Module: "kernel32.dll", Name: "GetTickCount"},
		APIImport{Module: "kernel32.dll", Name: "GetCurrentProcessId"})
	if _, err := NewWithLoader(context.Background(), bundle); err != nil {
		t.Fatalf("64-import bundle rejected: %v", err)
	}
	bundle.APIImports = append(bundle.APIImports, APIImport{Module: "kernel32.dll", Name: "GetCurrentThreadId"})
	if _, err := NewWithLoader(context.Background(), bundle); err == nil || !strings.Contains(err.Error(), "1..64") {
		t.Fatalf("65-import bundle result = %v", err)
	}
	bundle.APIImports = bundle.APIImports[:62]
	bundle.APIImports[61] = bundle.APIImports[60]
	if _, err := NewWithLoader(context.Background(), bundle); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate API result = %v", err)
	}
	bundle.APIImports[61] = APIImport{Module: "../advapi32.dll", Name: "GetUserNameA"}
	if _, err := NewWithLoader(context.Background(), bundle); err == nil || !strings.Contains(err.Error(), "invalid DLL name") {
		t.Fatalf("unsafe DLL name result = %v", err)
	}
	bundle.APIImports[61] = APIImport{Module: "advapi32.dll", Name: "GetUserNameA"}
	bundle.APIImports[1] = APIImport{Module: "kernel32.dll", Name: "GetCurrentThreadId"}
	if _, err := NewWithLoader(context.Background(), bundle); err == nil || !strings.Contains(err.Error(), "missing required API import") {
		t.Fatalf("omitted baseline API result = %v", err)
	}
}
