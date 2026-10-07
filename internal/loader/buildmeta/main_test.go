package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sliverarmory/churro/internal/wire"
)

func TestPinnedHeadersParseAndSeededRotation(t *testing.T) {
	includeDir := filepath.Join("..", "include")
	pinnedData, err := os.ReadFile(filepath.Join(includeDir, "poly_seed.h"))
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := parsePoly(pinnedData)
	if err != nil {
		t.Fatal(err)
	}
	if pinned.CipherRounds != 20 || pinned.HashRounds != 27 || pinned.CipherRotations != [6]uint32{4, 4, 16, 23, 22, 11} {
		t.Fatalf("unexpected pinned Poly constants: %+v", pinned)
	}
	master, err := os.ReadFile(filepath.Join(includeDir, "api_master.h"))
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	if err := os.WriteFile(filepath.Join(temp, "api_master.h"), master, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rotate(temp, 0xda44b96c); err != nil {
		t.Fatal(err)
	}
	generatedData, err := os.ReadFile(filepath.Join(temp, "poly_seed.h"))
	if err != nil {
		t.Fatal(err)
	}
	generated, err := parsePoly(generatedData)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(generated, pinned) {
		t.Fatalf("seeded Poly constants differ: got %+v, want %+v", generated, pinned)
	}
	apiData, err := os.ReadFile(filepath.Join(temp, "api_shuffle.h"))
	if err != nil {
		t.Fatal(err)
	}
	imports, err := parseAPIImports(apiData)
	if err != nil {
		t.Fatal(err)
	}
	if len(imports) != 61 || imports[0] != (apiImport{Module: "kernel32.dll", Name: "LoadLibraryA"}) {
		t.Fatalf("unexpected API shuffle: first=%+v count=%d", imports[0], len(imports))
	}
	if err := rotate(temp, 0xda44b96c); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join(temp, "api_shuffle.h"))
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != string(apiData) {
		t.Fatal("same seed produced a different API order")
	}
}

func TestEmbeddedDefaultsMatchPinnedHeaders(t *testing.T) {
	includeDir := filepath.Join("..", "include")
	polyData, err := os.ReadFile(filepath.Join(includeDir, "poly_seed.h"))
	if err != nil {
		t.Fatal(err)
	}
	pinnedPoly, err := parsePoly(polyData)
	if err != nil {
		t.Fatal(err)
	}
	wantPoly := wire.Poly{
		CipherRotations: pinnedPoly.CipherRotations,
		CipherRounds:    pinnedPoly.CipherRounds,
		HashRotA:        pinnedPoly.HashRotA,
		HashRotB:        pinnedPoly.HashRotB,
		HashRounds:      pinnedPoly.HashRounds,
	}
	if wire.DefaultPoly != wantPoly {
		t.Fatalf("generated Go Poly constants differ from native headers: got %+v, want %+v", wire.DefaultPoly, wantPoly)
	}
	apiData, err := os.ReadFile(filepath.Join(includeDir, "api_shuffle.h"))
	if err != nil {
		t.Fatal(err)
	}
	imports, err := parseAPIImports(apiData)
	if err != nil {
		t.Fatal(err)
	}
	if len(imports) != len(wire.DefaultAPIImports) {
		t.Fatalf("generated Go API count %d differs from native header %d", len(wire.DefaultAPIImports), len(imports))
	}
	for i, imp := range imports {
		if imp.Module != wire.DefaultAPIImports[i].Module || imp.Name != wire.DefaultAPIImports[i].Name {
			t.Fatalf("generated Go API slot %d differs from native header", i)
		}
	}
}
