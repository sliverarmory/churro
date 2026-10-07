package churro

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/sliverarmory/churro/internal/assets"
	"github.com/sliverarmory/churro/internal/wire"
)

// PolyConfig contains the cipher and hash constants compiled into a loader.
// A custom bundle must supply values from the same native build as its images.
type PolyConfig struct {
	CipherRotations [6]uint32 `json:"cipher_rotations"`
	CipherRounds    uint32    `json:"cipher_rounds"`
	HashRotA        uint32    `json:"hash_rot_a"`
	HashRotB        uint32    `json:"hash_rot_b"`
	HashRounds      uint32    `json:"hash_rounds"`
}

// APIImport is one DLL/export pair in the loader's API hash table.
type APIImport struct {
	Module string `json:"module"`
	Name   string `json:"name"`
}

// LoaderFunction is one section in an extracted native loader image.
type LoaderFunction struct {
	Offset     uint32 `json:"offset"`
	Size       uint32 `json:"size"`
	SinglePage bool   `json:"single_page"`
	Name       string `json:"name"`
}

// LoaderReference describes one cross-section relative instruction that must
// be redirected through a dispatch thunk in a multi-section loader.
type LoaderReference struct {
	SrcBlobOff uint32 `json:"src_blob_off"`
	InstLength uint16 `json:"inst_length"`
	DispOffset uint16 `json:"disp_offset"`
	SrcFn      uint16 `json:"src_fn"`
	TargetFn   uint16 `json:"target_fn"`
}

// LoaderMetadata is the section and cross-section reference table emitted
// with a native loader image by the PE extractor.
type LoaderMetadata struct {
	Functions  []LoaderFunction  `json:"functions"`
	References []LoaderReference `json:"references"`
}

// LoaderBundle is a set of x64 native loader images and matching metadata.
// The PEB variants, shim, Poly constants, and API order must all come from
// one native build. NewWithLoader validates their structure and takes a copy.
type LoaderBundle struct {
	PEB1         []byte
	PEB2         []byte
	DispatchShim []byte
	PEB1Meta     LoaderMetadata
	PEB2Meta     LoaderMetadata
	Poly         PolyConfig
	APIImports   []APIImport
}

// EmbeddedLoaderBundle returns a caller-owned copy of the built-in loader.
func EmbeddedLoaderBundle() LoaderBundle {
	peb1Meta, err := embeddedLoaderMetadata(false)
	if err != nil {
		panic(err)
	}
	peb2Meta, err := embeddedLoaderMetadata(true)
	if err != nil {
		panic(err)
	}
	imports := make([]APIImport, len(wire.DefaultAPIImports))
	for i, imp := range wire.DefaultAPIImports {
		imports[i] = APIImport{Module: imp.Module, Name: imp.Name}
	}
	return LoaderBundle{
		PEB1:         append([]byte(nil), assets.LoaderPEB1...),
		PEB2:         append([]byte(nil), assets.LoaderPEB2...),
		DispatchShim: append([]byte(nil), assets.DispatchShim...),
		PEB1Meta:     peb1Meta,
		PEB2Meta:     peb2Meta,
		Poly: PolyConfig{
			CipherRotations: wire.DefaultPoly.CipherRotations,
			CipherRounds:    wire.DefaultPoly.CipherRounds,
			HashRotA:        wire.DefaultPoly.HashRotA,
			HashRotB:        wire.DefaultPoly.HashRotB,
			HashRounds:      wire.DefaultPoly.HashRounds,
		},
		APIImports: imports,
	}
}

func (b LoaderBundle) clone() LoaderBundle {
	b.PEB1 = append([]byte(nil), b.PEB1...)
	b.PEB2 = append([]byte(nil), b.PEB2...)
	b.DispatchShim = append([]byte(nil), b.DispatchShim...)
	b.PEB1Meta.Functions = append([]LoaderFunction(nil), b.PEB1Meta.Functions...)
	b.PEB1Meta.References = append([]LoaderReference(nil), b.PEB1Meta.References...)
	b.PEB2Meta.Functions = append([]LoaderFunction(nil), b.PEB2Meta.Functions...)
	b.PEB2Meta.References = append([]LoaderReference(nil), b.PEB2Meta.References...)
	b.APIImports = append([]APIImport(nil), b.APIImports...)
	return b
}

func (b LoaderBundle) validate() error {
	if len(b.PEB1) == 0 || len(b.PEB2) == 0 || len(b.DispatchShim) < 28 {
		return errors.New("loader bundle requires two PEB images and a dispatch shim")
	}
	if len(b.PEB1) > math.MaxInt32 || len(b.PEB2) > math.MaxInt32 || len(b.DispatchShim) > math.MaxInt32 {
		return errors.New("loader bundle image exceeds size limit")
	}
	for _, marker := range [][]byte{
		{0x01, 0x00, 0xad, 0xde}, {0x02, 0x00, 0xad, 0xde},
		{0xb1, 0x7a, 0x7e, 0xf1, 0xb1, 0x7a, 0x7e, 0xf1},
	} {
		if bytes.Count(b.DispatchShim, marker) != 1 {
			return errors.New("loader bundle dispatch shim has missing or repeated metadata")
		}
	}
	if err := validateLoaderMetadata(b.PEB1Meta, b.PEB1); err != nil {
		return fmt.Errorf("PEB1 metadata: %w", err)
	}
	if err := validateLoaderMetadata(b.PEB2Meta, b.PEB2); err != nil {
		return fmt.Errorf("PEB2 metadata: %w", err)
	}
	for _, rotation := range b.Poly.CipherRotations {
		if rotation == 0 || rotation >= 32 {
			return errors.New("loader bundle has invalid cipher rotation")
		}
	}
	if b.Poly.CipherRounds == 0 || b.Poly.CipherRounds > 64 ||
		b.Poly.HashRounds == 0 || b.Poly.HashRounds > 64 ||
		b.Poly.HashRotA == 0 || b.Poly.HashRotA >= 32 ||
		b.Poly.HashRotB == 0 || b.Poly.HashRotB >= 32 {
		return errors.New("loader bundle has invalid cipher or hash rounds")
	}
	if len(b.APIImports) != len(wire.DefaultAPIImports) {
		return fmt.Errorf("loader bundle needs %d API imports", len(wire.DefaultAPIImports))
	}
	if b.APIImports[0].Module != "kernel32.dll" || b.APIImports[0].Name != "LoadLibraryA" {
		return errors.New("loader bundle must keep LoadLibraryA in the first API slot")
	}
	want := make(map[APIImport]int, len(wire.DefaultAPIImports))
	for _, imp := range wire.DefaultAPIImports {
		want[APIImport{Module: imp.Module, Name: imp.Name}]++
	}
	for _, imp := range b.APIImports {
		key := APIImport{Module: imp.Module, Name: imp.Name}
		want[key]--
		if want[key] < 0 {
			return fmt.Errorf("loader bundle has unexpected or duplicate API import %s!%s", imp.Module, imp.Name)
		}
	}
	return nil
}

func validateLoaderMetadata(meta LoaderMetadata, image []byte) error {
	if len(meta.Functions) == 0 || len(meta.Functions) > 16 {
		return errors.New("function count must be 1..16")
	}
	if len(meta.Functions) > 1 && len(meta.Functions)+1 > shimMaxFunctions {
		return errors.New("multi-section loader exceeds dispatch table capacity")
	}
	if meta.Functions[0].Offset != 0 {
		return errors.New("entry function must start at image offset zero")
	}
	for i, fn := range meta.Functions {
		end := uint64(fn.Offset) + uint64(fn.Size)
		if fn.Size == 0 || end > uint64(len(image)) {
			return fmt.Errorf("function %d exceeds loader image", i)
		}
		if fn.Name == "" || len(fn.Name) > 16 || strings.IndexByte(fn.Name, 0) >= 0 {
			return fmt.Errorf("function %d has an invalid name", i)
		}
		if fn.SinglePage && fn.Offset/4096 != uint32((end-1)/4096) {
			return fmt.Errorf("function %d is marked single_page but crosses a page", i)
		}
		for j := 0; j < i; j++ {
			other := meta.Functions[j]
			if uint64(fn.Offset) < uint64(other.Offset)+uint64(other.Size) &&
				uint64(other.Offset) < end {
				return fmt.Errorf("functions %d and %d overlap", j, i)
			}
		}
	}
	seenDisp := make(map[uint32]struct{}, len(meta.References))
	for i, ref := range meta.References {
		if int(ref.SrcFn) >= len(meta.Functions) || int(ref.TargetFn) >= len(meta.Functions) {
			return fmt.Errorf("reference %d has invalid function index", i)
		}
		if ref.SrcFn == ref.TargetFn {
			return fmt.Errorf("reference %d does not cross functions", i)
		}
		if ref.InstLength < 4 || uint32(ref.DispOffset)+4 > uint32(ref.InstLength) ||
			uint64(ref.SrcBlobOff)+uint64(ref.InstLength) > uint64(len(image)) {
			return fmt.Errorf("reference %d has invalid instruction bounds", i)
		}
		src := meta.Functions[ref.SrcFn]
		if ref.SrcBlobOff < src.Offset ||
			uint64(ref.SrcBlobOff)+uint64(ref.InstLength) > uint64(src.Offset)+uint64(src.Size) {
			return fmt.Errorf("reference %d is outside its source function", i)
		}
		disp := ref.SrcBlobOff + uint32(ref.DispOffset)
		if _, duplicate := seenDisp[disp]; duplicate {
			return fmt.Errorf("reference %d repeats a source displacement", i)
		}
		seenDisp[disp] = struct{}{}
	}
	return nil
}

func (b LoaderBundle) wireMetadata() (wire.Poly, []wire.APIImport) {
	poly := wire.Poly{
		CipherRotations: b.Poly.CipherRotations,
		CipherRounds:    b.Poly.CipherRounds,
		HashRotA:        b.Poly.HashRotA,
		HashRotB:        b.Poly.HashRotB,
		HashRounds:      b.Poly.HashRounds,
	}
	imports := make([]wire.APIImport, len(b.APIImports))
	for i, imp := range b.APIImports {
		imports[i] = wire.APIImport{Module: imp.Module, Name: imp.Name}
	}
	return poly, imports
}
