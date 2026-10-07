package churro

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
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
		if residentLoaderFunction(callee) {
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
	sizeSentinel := []byte{0x02, 0x00, 0xad, 0xde}
	sizeAt := bytes.Index(assets.DispatchShim, sizeSentinel)
	if sizeAt < 0 {
		t.Fatal("source shim size sentinel missing")
	}
	if got := binary.LittleEndian.Uint32(combined[sizeAt:]); got != uint32(len(assets.LoaderPEB1)+prePad+dispatchSlotSize+protected*dispatchThunkSize) {
		t.Fatalf("shim protection/wipe size=%d excludes dispatcher tail", got)
	}
}

func TestHashSectionUsesSynchronizedDispatch(t *testing.T) {
	meta, err := embeddedLoaderMetadata(false)
	if err != nil {
		t.Fatal(err)
	}
	hashID := -1
	for i, fn := range meta.Functions {
		if fn.Name == ".hash_ch" {
			hashID = i
			if residentLoaderFunction(fn) {
				t.Fatal("hash section must be protected")
			}
			break
		}
	}
	if hashID < 0 {
		t.Fatal("hash section missing")
	}
	incoming := 0
	for _, ref := range meta.References {
		if int(ref.TargetFn) == hashID {
			incoming++
		}
	}
	if incoming == 0 {
		t.Fatal("hash section has no dispatched callers")
	}
	combined, err := prepareCombinedWithMetadata(assets.LoaderPEB1, assets.DispatchShim, meta, repeatByte(0xa5))
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte{0xb1, 0x7a, 0x7e, 0xf1, 0xb1, 0x7a, 0x7e, 0xf1}
	ft := bytes.Index(assets.DispatchShim, marker)
	if ft < 0 {
		t.Fatal("source shim function table marker missing")
	}
	entry := combined[ft+16+hashID*12 : ft+28+hashID*12]
	if entry[8] == 0 || entry[9] != 0 || binary.LittleEndian.Uint16(entry[10:12]) != 0 {
		t.Fatalf("hash section key/flags/state = %x", entry[8:12])
	}
	section := meta.Functions[hashID]
	for j := uint32(0); j < section.Size; j++ {
		at := section.Offset + j
		if combined[4096+at]^entry[8] != assets.LoaderPEB1[at] {
			t.Fatalf("hash section byte %d was not encrypted with its key", j)
		}
	}
}

func TestMultiSectionRejectsUnalignedTransitionState(t *testing.T) {
	meta, err := embeddedLoaderMetadata(false)
	if err != nil {
		t.Fatal(err)
	}
	// Shift the marker one byte while keeping the sentinels and table intact.
	shim := append([]byte{0x90}, assets.DispatchShim...)
	_, err = prepareCombinedWithMetadata(assets.LoaderPEB1, shim, meta, repeatByte(0xa5))
	if err == nil || !strings.Contains(err.Error(), "not 2-byte aligned") {
		t.Fatalf("unaligned dispatcher state accepted: %v", err)
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
			if uint16(target) != ref.SrcFn && uint16(target) != ref.TargetFn && !residentLoaderFunction(meta.Functions[target]) {
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

func TestMultiSectionRejectsNonCallProtectedReferences(t *testing.T) {
	for _, fixture := range []struct {
		name       string
		opcode     []byte
		instLength uint16
		dispOffset uint16
	}{
		{"JMP", []byte{0xe9}, 5, 1},
		{"Jcc", []byte{0x0f, 0x85}, 6, 2},
		{"LEA", []byte{0x48, 0x8d, 0x05}, 7, 3},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			meta, err := embeddedLoaderMetadata(false)
			if err != nil {
				t.Fatal(err)
			}
			image := bytes.Clone(assets.LoaderPEB1)
			changed := false
			for i, ref := range meta.References {
				if residentLoaderFunction(meta.Functions[ref.TargetFn]) {
					continue
				}
				source := meta.Functions[ref.SrcFn]
				if uint64(ref.SrcBlobOff)+uint64(fixture.instLength) > uint64(source.Offset)+uint64(source.Size) {
					continue
				}
				copy(image[ref.SrcBlobOff:], fixture.opcode)
				meta.References[i].InstLength = fixture.instLength
				meta.References[i].DispOffset = fixture.dispOffset
				changed = true
				break
			}
			if !changed {
				t.Fatal("no protected callsite suitable for fixture")
			}
			_, err = prepareCombinedWithMetadata(image, assets.DispatchShim, meta, repeatByte(0xa5))
			if err == nil || !strings.Contains(err.Error(), "not CALL rel32") {
				t.Fatalf("expected unsupported reference error, got %v", err)
			}
		})
	}
}

func TestNativeDispatcherRIPTargets(t *testing.T) {
	const self, loader, table = uint32(12345), uint32(4096), uint32(931)
	seen := make(map[string]bool)
	maxSize := 0
	for seed := int64(0); seed < 2048; seed++ {
		for _, swapped := range []bool{false, true} {
			dispatcher, err := emitNativeDispatcher(self, loader, table, swapped, rand.New(rand.NewSource(seed)))
			if err != nil {
				t.Fatalf("seed %d swapped %v: %v", seed, swapped, err)
			}
			if len(dispatcher) == 0 || len(dispatcher) > dispatchSlotSize {
				t.Fatalf("seed %d swapped %v: dispatcher has %d bytes", seed, swapped, len(dispatcher))
			}
			if len(dispatcher) > maxSize {
				maxSize = len(dispatcher)
			}
			if dispatcher[len(dispatcher)-1] != 0xc3 ||
				!bytes.Contains(dispatcher, []byte{0x48, 0x83, 0xec, 0x60}) ||
				!bytes.Contains(dispatcher, []byte{0x48, 0x83, 0xc4, 0x60}) {
				t.Fatalf("seed %d swapped %v: broken dispatcher frame", seed, swapped)
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
					t.Fatalf("seed %d: RIP-relative LEA %x missing", seed, check.pattern)
				}
				rel := int32(binary.LittleEndian.Uint32(dispatcher[at+3 : at+7]))
				if got := int64(self) + int64(at+7) + int64(rel); got != int64(check.target) {
					t.Fatalf("seed %d: RIP-relative LEA resolves to %d, want %d", seed, got, check.target)
				}
			}
			seen[string(dispatcher)] = true
		}
	}
	if len(seen) < 2048 {
		t.Fatalf("only %d distinct dispatchers across 4096 sampled outputs", len(seen))
	}
	t.Logf("largest synchronized dispatcher across 4096 outputs: %d/%d bytes", maxSize, dispatchSlotSize)
}

func TestNativeDispatcherSlotBoundExtremes(t *testing.T) {
	for _, pattern := range []byte{0x00, 0x01, 0x07, 0x55, 0xaa, 0xff} {
		for _, swapped := range []bool{false, true} {
			code, err := emitNativeDispatcher(12345, 4096, 931, swapped, repeatByte(pattern))
			if err != nil || len(code) > dispatchSlotSize {
				t.Fatalf("pattern %02x swapped %v: size %d, error %v", pattern, swapped, len(code), err)
			}
		}
	}
}

func TestNativeDispatcherTransitionStateEncoding(t *testing.T) {
	for _, base := range []byte{12, 13, 14, 15} {
		e := nativeDispatchEmitter{}
		e.stateBit(base, false)
		e.stateCompare(base, 0x8000)
		e.stateCount(base, false)
		e.stateCount(base, true)
		e.stateBit(base, true)
		if got := bytes.Count(e.code, []byte{0x66, 0xf0, 0x41, 0x0f, 0xba}); got != 2 {
			t.Fatalf("r%d: expected atomic lock acquisition and release, got %d", base, got)
		}
		if !bytes.Contains(e.code, []byte{0x00, 0x80}) {
			t.Fatalf("r%d: zero-count comparison must include the held lock bit", base)
		}
		if len(e.code) == 0 || e.code[len(e.code)-1] != 15 {
			t.Fatalf("r%d: transition bit 15 encoding missing", base)
		}
	}
}

func TestNativeDispatcherXOROnlyAtZeroCount(t *testing.T) {
	code, err := emitNativeDispatcher(12345, 4096, 931, false, repeatByte(0x02))
	if err != nil {
		t.Fatal(err)
	}
	var checks []int
	for _, base := range []byte{12, 13, 14, 15} {
		cmp := nativeDispatchEmitter{}
		cmp.stateCompare(base, 0x8000)
		for search := 0; search < len(code); {
			at := bytes.Index(code[search:], cmp.code)
			if at < 0 {
				break
			}
			checks = append(checks, search+at+len(cmp.code))
			search += at + len(cmp.code)
		}
	}
	if len(checks) != 2 {
		t.Fatalf("zero-count transition guards = %d, want two", len(checks))
	}
	for _, at := range checks {
		if at+2 > len(code) || code[at] != 0x75 {
			t.Fatalf("transition at %d does not skip XOR on nonzero count", at)
		}
		skip := at + 2 + int(int8(code[at+1]))
		if skip <= at+2 || skip > len(code) || !bytes.Contains(code[at+2:skip], []byte{0x44, 0x30}) {
			t.Fatalf("transition at %d does not guard an XOR loop", at)
		}
	}
}

func TestNativeXORLoopShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		rnd  []byte
		want string
	}{
		{"forward counter rcx", []byte{0, 0, 0, 0, 0, 0, 0}, "4489f144303848ffc0ffc975f6"},
		{"reverse counter rcx", []byte{0, 1, 0, 0, 0, 0, 0}, "4c01f048ffc84489f144303848ffc8ffc975f6"},
		{"forward address rcx", []byte{0, 0, 1, 0, 0, 0, 0}, "4a8d0c3044303848ffc04839c875f5"},
		{"reverse address rcx", []byte{0, 1, 1, 0, 0, 0, 0}, "488d48ff4c01f048ffc844303848ffc84839c875f5"},
		{"forward counter r8", []byte{4, 0, 0, 0, 0, 0, 0}, "4589f044303848ffc041ffc875f5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := nativeDispatchEmitter{entropy: bytes.NewReader(tc.rnd)}
			e.xorLoop(14, 15)
			if e.err != nil {
				t.Fatal(e.err)
			}
			want, err := hex.DecodeString(tc.want)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(e.code, want) {
				t.Fatalf("loop bytes = %x, want %x", e.code, want)
			}
		})
	}
}

func TestNativeDispatcherStateLoads(t *testing.T) {
	e := nativeDispatchEmitter{}
	e.stateLoad(13, 12, 0, false) // r12 base needs SIB
	e.stateLoad(14, 13, 4, false) // r13 base needs disp8, even for zero
	e.stateLoad(15, 12, 8, true)
	want, err := hex.DecodeString("458b6c2400458b7504450fb67c2408")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(e.code, want) {
		t.Fatalf("state loads = %x, want %x", e.code, want)
	}
}

func TestNativeDispatcherEntropyFailure(t *testing.T) {
	if _, err := emitNativeDispatcher(12345, 4096, 931, false, bytes.NewReader(nil)); err == nil {
		t.Fatal("expected entropy exhaustion error")
	}
}
