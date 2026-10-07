package wire

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The build metadata and embedded loader images are a set. These checks make
// rebuilding the images without updating host-side Go constants fail CI.
func TestPolyConstantsMatchCheckedInHeader(t *testing.T) {
	data, err := os.ReadFile("../assets/poly_seed.h")
	if err != nil {
		t.Fatal(err)
	}
	definitions := map[string]uint32{}
	pattern := regexp.MustCompile(`(?m)^#define\s+([A-Z][A-Z0-9_]*)\s+([0-9]+)\s*$`)
	for _, match := range pattern.FindAllStringSubmatch(string(data), -1) {
		value, err := strconv.ParseUint(match[2], 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		definitions[match[1]] = uint32(value)
	}
	expected := map[string]uint32{
		"CIPHER_R0":     DefaultPoly.CipherRotations[0],
		"CIPHER_R1":     DefaultPoly.CipherRotations[1],
		"CIPHER_R2":     DefaultPoly.CipherRotations[2],
		"CIPHER_R3":     DefaultPoly.CipherRotations[3],
		"CIPHER_R4":     DefaultPoly.CipherRotations[4],
		"CIPHER_R5":     DefaultPoly.CipherRotations[5],
		"CIPHER_ROUNDS": DefaultPoly.CipherRounds,
		"HASH_ROT_A":    DefaultPoly.HashRotA,
		"HASH_ROT_B":    DefaultPoly.HashRotB,
		"HASH_ROUNDS":   DefaultPoly.HashRounds,
	}
	for name, want := range expected {
		if got := definitions[name]; got != want {
			t.Errorf("%s = %d in copied header, %d in Go", name, got, want)
		}
	}
}

func TestAPIOrderMatchesCheckedInHeader(t *testing.T) {
	data, err := os.ReadFile("../assets/api_shuffle.h")
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`(?m)^XAPI\(([A-Z0-9_]+),\s*"([^"]+)"`)
	matches := pattern.FindAllStringSubmatch(string(data), -1)
	if len(matches) != len(DefaultAPIImports) {
		t.Fatalf("copied header has %d APIs, Go has %d", len(matches), len(DefaultAPIImports))
	}
	for i, match := range matches {
		module := strings.ToLower(strings.TrimSuffix(match[1], "_DLL")) + ".dll"
		if got := DefaultAPIImports[i]; got.Module != module || got.Name != match[2] {
			t.Errorf("API slot %d: copied header %s/%s, Go %s/%s", i, module, match[2], got.Module, got.Name)
		}
	}
}
