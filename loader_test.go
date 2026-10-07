package churro

import (
	"bytes"
	"encoding/binary"
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
	combinedSize := 4096 + len(assets.LoaderPEB2)
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
	for i := 4096; i < len(combined); i++ {
		combined[i] ^= seed
	}
	if !bytes.Equal(combined[4096:], assets.LoaderPEB2) {
		t.Fatal("dispatch key does not reveal selected loader image")
	}
	decoderAt := prefix + 5 + len(instance) + 1 + 22 // fixed RSP entry
	if result[decoderAt] != 0x51 || result[decoderAt+1] != 0x48 {
		t.Fatal("decoder does not begin at the expected entry")
	}
	keyTarget := decoderAt + 8 + int(binary.LittleEndian.Uint32(result[decoderAt+4:decoderAt+8]))
	if !bytes.Equal(result[keyTarget:keyTarget+4], bytes.Repeat([]byte{seed}, 4)) {
		t.Fatal("decoder key RIP displacement is wrong")
	}
	dataTarget := decoderAt + 15 + int(binary.LittleEndian.Uint32(result[decoderAt+11:decoderAt+15]))
	if dataTarget != combinedAt {
		t.Fatalf("decoder data target %d, want %d", dataTarget, combinedAt)
	}
}

func TestPrepareCombinedRejectsMissingMetadata(t *testing.T) {
	if _, err := prepareCombined([]byte{1}, []byte{1, 2, 3}, repeatByte(1)); err == nil {
		t.Fatal("expected malformed shim error")
	}
}
