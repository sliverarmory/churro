package churro

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/sliverarmory/churro/internal/assets"
)

type repeatByte byte

func (r repeatByte) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

func TestLoaderLayoutAndDecoderTargets(t *testing.T) {
	instance := []byte("instance fixture")
	const seed = 0xa5
	result, err := buildLoader(instance, repeatByte(seed))
	if err != nil {
		t.Fatal(err)
	}
	prefix := seed & 0x3f
	if result[prefix] != 0xe8 || binary.LittleEndian.Uint32(result[prefix+1:]) != uint32(len(instance)) {
		t.Fatal("entry CALL does not skip the instance")
	}
	if !bytes.Equal(result[prefix+5:prefix+5+len(instance)], instance) {
		t.Fatal("instance bytes changed in loader")
	}
	if result[prefix+5+len(instance)] != 0x59 {
		t.Fatal("instance address is not popped into RCX")
	}
	meta, err := embeddedLoaderMetadata(true)
	if err != nil {
		t.Fatal(err)
	}
	protectedRefs := 0
	for _, ref := range meta.References {
		if !residentLoaderFunction(meta.Functions[ref.TargetFn]) {
			protectedRefs++
		}
	}
	combinedSize := 4096 + len(assets.LoaderPEB2) + (seed & 63) + dispatchSlotSize + protectedRefs*dispatchThunkSize
	combinedAt := len(result) - combinedSize
	if combinedAt%4096 != 0 {
		t.Fatalf("shim begins at %d, not a page boundary", combinedAt)
	}
	combined := bytes.Clone(result[combinedAt:])
	for i := range combined {
		combined[i] ^= seed
	}
	if combined[0] != assets.DispatchShim[0] || combined[1] != assets.DispatchShim[1] {
		t.Fatal("outer decoder does not reveal the dispatch shim")
	}
	marker := []byte{0xb1, 0x7a, 0x7e, 0xf1, 0xb1, 0x7a, 0x7e, 0xf1}
	ft := bytes.Index(assets.DispatchShim, marker)
	if ft < 0 {
		t.Fatal("source shim has no function table")
	}
	if got := binary.LittleEndian.Uint32(combined[ft+8:]); got != uint32(len(meta.Functions)+1) {
		t.Fatalf("function count=%d, want %d", got, len(meta.Functions)+1)
	}
	for i, fn := range meta.Functions {
		entry := combined[ft+16+i*12 : ft+28+i*12]
		if got := binary.LittleEndian.Uint32(entry[:4]); got != fn.Offset {
			t.Fatalf("function %d offset=%d, want %d", i, got, fn.Offset)
		}
		if got := binary.LittleEndian.Uint32(entry[4:8]); got != fn.Size {
			t.Fatalf("function %d size=%d, want %d", i, got, fn.Size)
		}
		if residentLoaderFunction(fn) && (entry[8] != 0 || entry[9] != 1) {
			t.Fatalf("resident function %q has incorrect dispatch flags", fn.Name)
		}
		if !residentLoaderFunction(fn) && (entry[8] == 0 || entry[9] != 0) {
			t.Fatalf("protected function %d has incorrect key or flags", i)
		}
	}
}

func TestPolymorphicDecoderTargetsAndVariants(t *testing.T) {
	const combinedSize = 5000
	var variants = make(map[string]bool)
	for seed := int64(1); seed <= 32; seed++ {
		rng := rand.New(rand.NewSource(seed))
		key := bytes.Repeat([]byte{byte(seed)}, []int{4, 8, 16}[seed%3])
		decoder, fixups, err := makeDecoder(combinedSize, key, rng)
		if err != nil {
			t.Fatal(err)
		}
		tramp, trampFixups, err := makeTrampoline(rng)
		if err != nil {
			t.Fatal(err)
		}
		pagePad := 121
		encodedStart := len(decoder) + len(tramp) + pagePad
		if err := patchDecoder(decoder, fixups, encodedStart); err != nil {
			t.Fatal(err)
		}
		patchTrampoline(tramp, trampFixups, pagePad)
		keyTarget := fixups.keyEnd + int(binary.LittleEndian.Uint32(decoder[fixups.keyDisp:]))
		dataTarget := fixups.dataEnd + int(binary.LittleEndian.Uint32(decoder[fixups.dataDisp:]))
		if keyTarget != fixups.keyStart || !bytes.Equal(decoder[keyTarget:keyTarget+len(key)], key) {
			t.Fatalf("seed %d decoder key displacement does not target key", seed)
		}
		if dataTarget != encodedStart {
			t.Fatalf("seed %d decoder data target=%d want=%d", seed, dataTarget, encodedStart)
		}
		trampTarget := trampFixups.leaEnd + int(binary.LittleEndian.Uint32(tramp[trampFixups.leaDisp:]))
		if trampTarget != len(tramp)+pagePad {
			t.Fatalf("seed %d trampoline target=%d", seed, trampTarget)
		}
		if !trampFixups.indirect {
			jmpTarget := trampFixups.jmpEnd + int(binary.LittleEndian.Uint32(tramp[trampFixups.jmpDisp:]))
			if jmpTarget != len(tramp)+pagePad {
				t.Fatalf("seed %d relative trampoline target=%d", seed, jmpTarget)
			}
		} else if !bytes.HasSuffix(tramp, []byte{0xff, 0xe2}) {
			t.Fatalf("seed %d indirect trampoline does not jump through RDX", seed)
		}
		variants[string(decoder[:len(decoder)-len(key)])] = true
	}
	if len(variants) < 20 {
		t.Fatalf("only %d distinct decoder forms across 32 seeds", len(variants))
	}
}

func TestPolymorphicStackEntryAndPrefix(t *testing.T) {
	var entries = map[string]bool{}
	var variedPrefix bool
	for seed := int64(1); seed <= 32; seed++ {
		rng := rand.New(rand.NewSource(seed))
		prefix, err := makePrefix(rng)
		if err != nil {
			t.Fatal(err)
		}
		if len(prefix) > 63 {
			t.Fatalf("seed %d prefix has %d bytes", seed, len(prefix))
		}
		if len(prefix) > 2 && !bytes.Equal(prefix, bytes.Repeat([]byte{0x90}, len(prefix))) {
			variedPrefix = true
		}
		entry, err := makeStackEntry(rng)
		if err != nil {
			t.Fatal(err)
		}
		if entry[len(entry)-1] != 0xc3 {
			t.Fatalf("seed %d entry does not end in RET", seed)
		}
		callFound := false
		for at := 0; at+5 <= len(entry); at++ {
			if entry[at] == 0xe8 && int(binary.LittleEndian.Uint32(entry[at+1:])) == len(entry)-at-5 {
				callFound = true
				break
			}
		}
		if !callFound {
			t.Fatalf("seed %d RSP entry CALL does not skip epilogue", seed)
		}
		entries[string(entry)] = true
	}
	if !variedPrefix || len(entries) < 20 {
		t.Fatalf("polymorphic entry/prefix variety too small: %d forms, varied prefix %v", len(entries), variedPrefix)
	}
}

func TestPrepareCombinedRejectsMissingMetadata(t *testing.T) {
	if _, err := prepareCombined([]byte{1}, []byte{1, 2, 3}, repeatByte(1)); err == nil {
		t.Fatal("expected malformed shim error")
	}
}
