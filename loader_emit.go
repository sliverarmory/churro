package churro

import (
	"encoding/binary"
	"fmt"
	"io"
)

func entropyByte(entropy io.Reader) (byte, error) {
	var value [1]byte
	_, err := io.ReadFull(entropy, value[:])
	return value[0], err
}

// randomNOP emits one architecturally inert x64 instruction. Its displacement
// bytes vary while the CPU ignores the memory operand of the 0F 1F opcode.
func randomNOP(entropy io.Reader, length int) ([]byte, error) {
	if length < 1 || length > 9 {
		return nil, fmt.Errorf("invalid NOP length %d", length)
	}
	var random [4]byte
	if _, err := io.ReadFull(entropy, random[:]); err != nil {
		return nil, err
	}
	switch length {
	case 1:
		return []byte{0x90}, nil
	case 2:
		return []byte{0x66, 0x90}, nil
	case 3:
		if random[0]&1 == 0 {
			return []byte{0x0f, 0x1f, 0x00}, nil
		}
		return []byte{0x0f, 0x1f, 0xc0}, nil
	case 4:
		return []byte{0x0f, 0x1f, 0x40, random[0]}, nil
	case 5:
		return []byte{0x0f, 0x1f, 0x44, 0x00, random[0]}, nil
	case 6:
		return []byte{0x66, 0x0f, 0x1f, 0x44, 0x00, random[0]}, nil
	case 7:
		return append([]byte{0x0f, 0x1f, 0x80}, random[:]...), nil
	case 8:
		return append([]byte{0x0f, 0x1f, 0x84, 0x00}, random[:]...), nil
	default:
		return append([]byte{0x66, 0x0f, 0x1f, 0x84, 0x00}, random[:]...), nil
	}
}

func makeJunk(entropy io.Reader, maxLength int) ([]byte, error) {
	if maxLength < 0 || maxLength > 63 {
		return nil, fmt.Errorf("invalid junk limit %d", maxLength)
	}
	choice, err := entropyByte(entropy)
	if err != nil {
		return nil, err
	}
	target := int(choice) % (maxLength + 1)
	junk := make([]byte, 0, target)
	for len(junk) < target {
		choice, err := entropyByte(entropy)
		if err != nil {
			return nil, err
		}
		chunk := 1 + int(choice)%min(target-len(junk), 9)
		nop, err := randomNOP(entropy, chunk)
		if err != nil {
			return nil, err
		}
		junk = append(junk, nop...)
	}
	return junk, nil
}

func makePrefix(entropy io.Reader) ([]byte, error) {
	choice, err := entropyByte(entropy)
	if err != nil {
		return nil, fmt.Errorf("select prefix length: %w", err)
	}
	target := int(choice & 0x3f)
	prefix := make([]byte, 0, target)
	for len(prefix) < target {
		choice, err := entropyByte(entropy)
		if err != nil {
			return nil, err
		}
		chunk := 1 + int(choice)%min(target-len(prefix), 9)
		nop, err := randomNOP(entropy, chunk)
		if err != nil {
			return nil, err
		}
		prefix = append(prefix, nop...)
	}
	return prefix, nil
}

// The entry saves one nonvolatile register as a stack-frame anchor. CALL
// enters the decoder while its return address points to this epilogue.
func makeStackEntry(entropy io.Reader) ([]byte, error) {
	registers := [...]byte{5, 13, 14, 15} // RBP, R13, R14, R15.
	choice, err := entropyByte(entropy)
	if err != nil {
		return nil, err
	}
	reg := registers[int(choice)%len(registers)]
	choice, err = entropyByte(entropy)
	if err != nil {
		return nil, err
	}
	saveWithLEA := choice&1 != 0
	choice, err = entropyByte(entropy)
	if err != nil {
		return nil, err
	}
	restoreWithLEA := choice&1 != 0
	low, high := reg&7, reg >= 8
	prologue := make([]byte, 0, 96)
	if high {
		prologue = append(prologue, 0x41)
	}
	prologue = append(prologue, 0x50|low) // push save register
	appendJunk := func(dst []byte) ([]byte, error) {
		junk, err := makeJunk(entropy, 4)
		return append(dst, junk...), err
	}
	if prologue, err = appendJunk(prologue); err != nil {
		return nil, err
	}
	if saveWithLEA {
		rex := byte(0x48)
		if high {
			rex |= 0x04 // REX.R
		}
		prologue = append(prologue, rex, 0x8d, low<<3|0x04, 0x24) // lea reg,[rsp]
	} else {
		rex := byte(0x48)
		if high {
			rex |= 0x01 // REX.B
		}
		prologue = append(prologue, rex, 0x89, 0xc0|4<<3|low) // mov reg,rsp
	}
	if prologue, err = appendJunk(prologue); err != nil {
		return nil, err
	}
	prologue = append(prologue, 0x48, 0x83, 0xe4, 0xf0) // and rsp,-16
	if prologue, err = appendJunk(prologue); err != nil {
		return nil, err
	}
	prologue = append(prologue, 0x48, 0x83, 0xec, 0x20) // reserve shadow space
	if prologue, err = appendJunk(prologue); err != nil {
		return nil, err
	}

	epilogue := make([]byte, 0, 32)
	if restoreWithLEA {
		rex := byte(0x48)
		if high {
			rex |= 0x01 // REX.B
		}
		epilogue = append(epilogue, rex, 0x8d, 0x60|low, 0x00) // lea rsp,[reg+0]
	} else {
		rex := byte(0x48)
		if high {
			rex |= 0x04 // REX.R
		}
		epilogue = append(epilogue, rex, 0x89, 0xc0|low<<3|4) // mov rsp,reg
	}
	if epilogue, err = appendJunk(epilogue); err != nil {
		return nil, err
	}
	if high {
		epilogue = append(epilogue, 0x41)
	}
	epilogue = append(epilogue, 0x58|low) // pop save register
	if epilogue, err = appendJunk(epilogue); err != nil {
		return nil, err
	}
	epilogue = append(epilogue, 0xc3)
	prologue = append(prologue, 0xe8)
	prologue = binary.LittleEndian.AppendUint32(prologue, uint32(len(epilogue)))
	return append(prologue, epilogue...), nil
}

type trampolineFixups struct {
	leaDisp, leaEnd int
	jmpDisp, jmpEnd int
	indirect        bool
}

func makeTrampoline(entropy io.Reader) ([]byte, trampolineFixups, error) {
	registers := [...]byte{2, 8, 9, 10, 11} // All volatile in the Win64 ABI.
	choice, err := entropyByte(entropy)
	if err != nil {
		return nil, trampolineFixups{}, err
	}
	reg := registers[int(choice)%len(registers)]
	rex := byte(0x48)
	if reg >= 8 {
		rex |= 0x04
	}
	tramp := []byte{rex, 0x8d, reg&7<<3 | 5}
	f := trampolineFixups{leaDisp: len(tramp)}
	tramp = append(tramp, 0, 0, 0, 0)
	f.leaEnd = len(tramp)
	if reg != 2 {
		tramp = append(tramp, rex, 0x89, 0xc0|(reg&7)<<3|2) // mov rdx,reg
	}
	junk, err := makeJunk(entropy, 6)
	if err != nil {
		return nil, trampolineFixups{}, err
	}
	tramp = append(tramp, junk...)
	choice, err = entropyByte(entropy)
	if err != nil {
		return nil, trampolineFixups{}, err
	}
	f.indirect = choice&1 != 0
	if f.indirect {
		tramp = append(tramp, 0xff, 0xe2) // jmp rdx
	} else {
		tramp = append(tramp, 0xe9)
		f.jmpDisp = len(tramp)
		tramp = append(tramp, 0, 0, 0, 0)
		f.jmpEnd = len(tramp)
	}
	return tramp, f, nil
}

func patchTrampoline(tramp []byte, f trampolineFixups, pagePad int) {
	encodedStart := len(tramp) + pagePad
	binary.LittleEndian.PutUint32(tramp[f.leaDisp:], uint32(encodedStart-f.leaEnd))
	if !f.indirect {
		binary.LittleEndian.PutUint32(tramp[f.jmpDisp:], uint32(encodedStart-f.jmpEnd))
	}
}

func rex(reg byte, wide, regField, index, base bool) byte {
	value := byte(0x40)
	if wide {
		value |= 8
	}
	if regField && reg >= 8 {
		value |= 4
	}
	if index && reg >= 8 {
		value |= 2
	}
	if base && reg >= 8 {
		value |= 1
	}
	return value
}

// makeDecoder varies register roles, zeroing opcode, update order, and inert
// instructions while preserving RCX, the instance pointer. All chosen scratch
// registers are volatile under the Win64 calling convention.
func makeDecoder(combinedSize uint32, key []byte, entropy io.Reader) ([]byte, decoderFixups, error) {
	if len(key) != 4 && len(key) != 8 && len(key) != 16 {
		return nil, decoderFixups{}, fmt.Errorf("invalid decoder key length %d", len(key))
	}
	pool := [...]byte{1, 2, 8, 9, 10, 11} // RCX, RDX, R8..R11.
	for i := len(pool) - 1; i > 0; i-- {
		choice, err := entropyByte(entropy)
		if err != nil {
			return nil, decoderFixups{}, err
		}
		j := int(choice) % (i + 1)
		pool[i], pool[j] = pool[j], pool[i]
	}
	keyPtr, dataPtr, counter, keyIndex := pool[0], pool[1], pool[2], pool[3]
	choice, err := entropyByte(entropy)
	if err != nil {
		return nil, decoderFixups{}, err
	}
	zeroOpcode := byte(0x31)
	if choice&1 != 0 {
		zeroOpcode = 0x29 // sub reg32,reg32
	}
	choice, err = entropyByte(entropy)
	if err != nil {
		return nil, decoderFixups{}, err
	}
	loopOrder := choice % 3
	d, err := makeJunk(entropy, 3)
	if err != nil {
		return nil, decoderFixups{}, err
	}
	d = append(d, 0x51) // preserve RCX (instance pointer)
	appendJunk := func() error {
		junk, err := makeJunk(entropy, 3)
		d = append(d, junk...)
		return err
	}
	if err := appendJunk(); err != nil {
		return nil, decoderFixups{}, err
	}
	emitLEA := func(reg byte) (int, int) {
		d = append(d, rex(reg, true, true, false, false), 0x8d, (reg&7)<<3|5)
		disp := len(d)
		d = append(d, 0, 0, 0, 0)
		return disp, len(d)
	}
	f := decoderFixups{}
	f.keyDisp, f.keyEnd = emitLEA(keyPtr)
	if err := appendJunk(); err != nil {
		return nil, decoderFixups{}, err
	}
	f.dataDisp, f.dataEnd = emitLEA(dataPtr)
	if err := appendJunk(); err != nil {
		return nil, decoderFixups{}, err
	}
	if counter >= 8 {
		d = append(d, 0x41)
	}
	d = append(d, 0xb8|(counter&7))
	d = binary.LittleEndian.AppendUint32(d, combinedSize)
	if err := appendJunk(); err != nil {
		return nil, decoderFixups{}, err
	}
	if keyIndex >= 8 {
		d = append(d, 0x45)
	}
	d = append(d, zeroOpcode, 0xc0|(keyIndex&7)<<3|(keyIndex&7))
	if err := appendJunk(); err != nil {
		return nil, decoderFixups{}, err
	}
	loopStart := len(d)
	// mov al,[keyPtr+keyIndex]
	sibRex := byte(0x40)
	if keyPtr >= 8 {
		sibRex |= 1
	}
	if keyIndex >= 8 {
		sibRex |= 2
	}
	if sibRex != 0x40 {
		d = append(d, sibRex)
	}
	d = append(d, 0x8a, 0x04, (keyIndex&7)<<3|(keyPtr&7))
	if err := appendJunk(); err != nil {
		return nil, decoderFixups{}, err
	}
	if dataPtr >= 8 {
		d = append(d, 0x41)
	}
	d = append(d, 0x30, dataPtr&7) // xor byte [dataPtr],al
	if err := appendJunk(); err != nil {
		return nil, decoderFixups{}, err
	}
	emitDataInc := func() { d = append(d, rex(dataPtr, true, false, false, true), 0xff, 0xc0|(dataPtr&7)) }
	emitIndexInc := func() {
		if keyIndex >= 8 {
			d = append(d, 0x41)
		}
		d = append(d, 0xfe, 0xc0|(keyIndex&7))
	}
	emitMask := func() {
		if keyIndex >= 8 {
			d = append(d, 0x41)
		}
		d = append(d, 0x80, 0xe0|(keyIndex&7), byte(len(key)-1))
	}
	switch loopOrder {
	case 0:
		emitDataInc()
		if err := appendJunk(); err != nil {
			return nil, decoderFixups{}, err
		}
		emitIndexInc()
		if err := appendJunk(); err != nil {
			return nil, decoderFixups{}, err
		}
		emitMask()
	case 1:
		emitIndexInc()
		if err := appendJunk(); err != nil {
			return nil, decoderFixups{}, err
		}
		emitDataInc()
		if err := appendJunk(); err != nil {
			return nil, decoderFixups{}, err
		}
		emitMask()
	default:
		emitIndexInc()
		if err := appendJunk(); err != nil {
			return nil, decoderFixups{}, err
		}
		emitMask()
		if err := appendJunk(); err != nil {
			return nil, decoderFixups{}, err
		}
		emitDataInc()
	}
	if err := appendJunk(); err != nil {
		return nil, decoderFixups{}, err
	}
	if counter >= 8 {
		d = append(d, 0x41)
	}
	d = append(d, 0xff, 0xc8|(counter&7), 0x75, 0)
	jnzEnd := len(d)
	rel := loopStart - jnzEnd
	if rel < -128 || rel > 127 {
		return nil, decoderFixups{}, fmt.Errorf("decoder loop exceeds short jump range")
	}
	d[jnzEnd-1] = byte(int8(rel))
	if err := appendJunk(); err != nil {
		return nil, decoderFixups{}, err
	}
	d = append(d, 0x59) // restore RCX
	if err := appendJunk(); err != nil {
		return nil, decoderFixups{}, err
	}
	d = append(d, 0xeb, byte(len(key))) // skip non-executable key bytes
	f.keyStart = len(d)
	d = append(d, key...)
	return d, f, nil
}
