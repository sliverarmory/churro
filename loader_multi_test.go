package churro

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/sliverarmory/churro/internal/assets"
)

func TestMultiSectionReferencesAndFunctionTable(t *testing.T) {
	meta, err := embeddedLoaderMetadata(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.Functions) < 2 || len(meta.References) == 0 {
		t.Fatal("embedded loader does not contain multi-section metadata")
	}
	const seed byte = 0xa5
	combined, err := prepareCombinedWithMetadata(assets.LoaderPEB1, assets.DispatchShim, meta, repeatByte(seed))
	if err != nil {
		t.Fatal(err)
	}
	const loaderStart = 4096
	prePad := int(seed & 63)
	dispatchAt := loaderStart + len(assets.LoaderPEB1) + prePad
	marker := []byte{0xb1, 0x7a, 0x7e, 0xf1, 0xb1, 0x7a, 0x7e, 0xf1}
	ft := bytes.Index(assets.DispatchShim, marker)
	if ft < 0 {
		t.Fatal("source shim function table marker missing")
	}
	protected := 0
	for i, ref := range meta.References {
		callee := meta.Functions[ref.TargetFn]
		if strings.HasPrefix(callee.Name, ".text") {
			continue
		}
		originalDispAt := int(ref.SrcBlobOff) + int(ref.DispOffset)
		originalRel := int32(binary.LittleEndian.Uint32(assets.LoaderPEB1[originalDispAt:]))
		originalTarget := int64(ref.SrcBlobOff) + int64(ref.InstLength) + int64(originalRel)
		if originalTarget < int64(callee.Offset) || originalTarget >= int64(callee.Offset+callee.Size) {
			t.Fatalf("reference %d source metadata resolves outside callee", i)
		}
		patched := bytes.Clone(combined[loaderStart+originalDispAt : loaderStart+originalDispAt+4])
		srcEntry := combined[ft+16+int(ref.SrcFn)*12 : ft+28+int(ref.SrcFn)*12]
		for j := range patched {
			patched[j] ^= srcEntry[8]
		}
		patchedRel := int32(binary.LittleEndian.Uint32(patched))
		patchedTarget := int64(ref.SrcBlobOff) + int64(ref.InstLength) + int64(patchedRel)
		wantThunk := int64(len(assets.LoaderPEB1) + prePad + dispatchSlotSize + protected*dispatchThunkSize)
		if patchedTarget != wantThunk {
			t.Fatalf("reference %d points to %d, want thunk %d", i, patchedTarget, wantThunk)
		}
		thunk := combined[loaderStart+int(wantThunk) : loaderStart+int(wantThunk)+dispatchThunkSize]
		if thunk[0] != 0x41 || thunk[6] != 0x41 || thunk[12] != 0xe9 {
			t.Fatalf("reference %d thunk has invalid instruction shape", i)
		}
		// The fixed test reader selects swapped registers and ID-first order.
		if thunk[1] != 0xba || thunk[7] != 0xbb ||
			binary.LittleEndian.Uint32(thunk[2:6]) != uint32(ref.TargetFn) ||
			binary.LittleEndian.Uint32(thunk[8:12]) != uint32(originalTarget) {
			t.Fatalf("reference %d thunk metadata does not match target", i)
		}
		dispatchRel := int32(binary.LittleEndian.Uint32(thunk[13:17]))
		if got := loaderStart + int(wantThunk) + dispatchThunkSize + int(dispatchRel); got != dispatchAt {
			t.Fatalf("reference %d thunk jumps to %d, want %d", i, got, dispatchAt)
		}
		protected++
	}
	if protected == 0 {
		t.Fatal("no protected references were checked")
	}
	tail := combined[ft+16+len(meta.Functions)*12 : ft+28+len(meta.Functions)*12]
	if got := binary.LittleEndian.Uint32(tail[:4]); got != uint32(len(assets.LoaderPEB1)) {
		t.Fatalf("resident tail offset=%d", got)
	}
	if got := binary.LittleEndian.Uint32(tail[4:8]); got != uint32(prePad+dispatchSlotSize+protected*dispatchThunkSize) {
		t.Fatalf("resident tail size=%d", got)
	}
	if tail[8] != 0 || tail[9] != 1 {
		t.Fatal("dispatcher tail is not resident")
	}
}

func TestMultiSectionRejectsMismatchedReferenceTarget(t *testing.T) {
	meta, err := embeddedLoaderMetadata(false)
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	for i, ref := range meta.References {
		for target := range meta.Functions {
			if uint16(target) != ref.SrcFn && uint16(target) != ref.TargetFn && meta.Functions[target].Name != ".text" {
				meta.References[i].TargetFn = uint16(target)
				changed = true
				break
			}
		}
		if changed {
			break
		}
	}
	if !changed {
		t.Fatal("no suitable metadata reference to corrupt")
	}
	_, err = prepareCombinedWithMetadata(assets.LoaderPEB1, assets.DispatchShim, meta, repeatByte(0xa5))
	if err == nil || !strings.Contains(err.Error(), "resolves outside target section") {
		t.Fatalf("expected target-section validation error, got %v", err)
	}
}

func TestNativeDispatcherRIPTargets(t *testing.T) {
	const self, loader, table = uint32(12345), uint32(4096), uint32(931)
	dispatcher := emitNativeDispatcher(self, loader, table, true)
	if len(dispatcher) == 0 || len(dispatcher) > dispatchSlotSize {
		t.Fatalf("dispatcher has %d bytes", len(dispatcher))
	}
	for _, check := range []struct {
		pattern []byte
		target  uint32
	}{
		{[]byte{0x48, 0x8d, 0x35}, table},
		{[]byte{0x48, 0x8d, 0x05}, loader},
	} {
		at := bytes.Index(dispatcher, check.pattern)
		if at < 0 {
			t.Fatalf("RIP-relative LEA %x missing", check.pattern)
		}
		rel := int32(binary.LittleEndian.Uint32(dispatcher[at+3 : at+7]))
		if got := int64(self) + int64(at+7) + int64(rel); got != int64(check.target) {
			t.Fatalf("RIP-relative LEA resolves to %d, want %d", got, check.target)
		}
	}
}
