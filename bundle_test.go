package churro

import (
	"context"
	"strings"
	"testing"
)

// These checks exercise metadata validation only. Executable N>1 loader
// behavior is covered by the native-loader integration tests.
func TestMultiSectionBundleMetadataValidation(t *testing.T) {
	bundle := EmbeddedLoaderBundle()
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
	if got := len(bundle.PEB2Meta.References); got != 60 {
		t.Fatalf("PEB2 reference count = %d, want 60", got)
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
