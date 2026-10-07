package wire

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"testing"
)

// referenceDepack follows the native loader's token decoder and checks the
// exact output length, including overlapping back references.
func referenceDepack(src, expected []byte) ([]byte, error) {
	want := len(expected)
	if len(src) == 0 || want <= 0 {
		return nil, fmt.Errorf("empty stream")
	}
	input := 1
	bits, available := byte(0), uint8(0)
	readByte := func() (byte, error) {
		if input == len(src) {
			return 0, fmt.Errorf("truncated stream")
		}
		value := src[input]
		input++
		return value, nil
	}
	readBit := func() (byte, error) {
		if available == 0 {
			value, err := readByte()
			if err != nil {
				return 0, err
			}
			bits, available = value, 8
		}
		value := bits >> 7
		bits <<= 1
		available--
		return value, nil
	}
	readGamma := func() (uint32, error) {
		value := uint32(1)
		for {
			data, err := readBit()
			if err != nil {
				return 0, err
			}
			cont, err := readBit()
			if err != nil {
				return 0, err
			}
			value = value<<1 | uint32(data)
			if cont == 0 {
				return value, nil
			}
		}
	}
	copyMatch := func(out []byte, offset, count int) ([]byte, error) {
		if offset <= 0 || offset > len(out) || len(out)+count > want {
			return nil, fmt.Errorf("invalid match offset=%d length=%d at=%d", offset, count, len(out))
		}
		for i := 0; i < count; i++ {
			out = append(out, out[len(out)-offset])
		}
		return out, nil
	}
	out := make([]byte, 1, want)
	out[0] = src[0]
	previousOffset, previousMatch := 0, false
	checked := 0
	op := "initial"
	for {
		for checked < len(out) {
			if checked >= want || out[checked] != expected[checked] {
				return nil, fmt.Errorf("mismatched byte at %d after %s (stream offset %d): got %x want %x", checked, op, input, out[checked], expected[checked])
			}
			checked++
		}
		lead, err := readBit()
		if err != nil {
			return nil, err
		}
		if lead == 0 {
			op = "literal"
			value, err := readByte()
			if err != nil {
				return nil, err
			}
			out = append(out, value)
			previousMatch = false
			continue
		}
		second, err := readBit()
		if err != nil {
			return nil, err
		}
		if second == 0 {
			op = "long"
			codedOffset, err := readGamma()
			if err != nil {
				return nil, err
			}
			if !previousMatch && codedOffset == 2 {
				count, err := readGamma()
				if err != nil {
					return nil, err
				}
				out, err = copyMatch(out, previousOffset, int(count))
				if err != nil {
					return nil, err
				}
			} else {
				if !previousMatch {
					codedOffset -= 3
				} else {
					codedOffset -= 2
				}
				low, err := readByte()
				if err != nil {
					return nil, err
				}
				offset := int(codedOffset<<8 | uint32(low))
				count, err := readGamma()
				if err != nil {
					return nil, err
				}
				if offset >= 32000 {
					count++
				}
				if offset >= 1280 {
					count++
				}
				if offset < 128 {
					count += 2
				}
				out, err = copyMatch(out, offset, int(count))
				if err != nil {
					return nil, err
				}
				previousOffset = offset
			}
			previousMatch = true
			continue
		}
		third, err := readBit()
		if err != nil {
			return nil, err
		}
		if third == 0 {
			value, err := readByte()
			if err != nil {
				return nil, err
			}
			offset := int(value >> 1)
			op = fmt.Sprintf("short off=%d len=%d at=%d", offset, 2+int(value&1), len(out))
			if offset == 0 {
				if len(out) != want {
					return nil, fmt.Errorf("unpacked %d bytes, want %d", len(out), want)
				}
				return out, nil
			}
			out, err = copyMatch(out, offset, 2+int(value&1))
			if err != nil {
				return nil, err
			}
			previousOffset, previousMatch = offset, true
			continue
		}
		offset := 0
		for i := 0; i < 4; i++ {
			bit, err := readBit()
			if err != nil {
				return nil, err
			}
			offset = offset<<1 | int(bit)
		}
		if offset == 0 {
			op = "zero"
			out = append(out, 0)
		} else {
			op = "single"
			out = append(out, out[len(out)-offset])
		}
		previousMatch = false
	}
}

func TestPackAPLibFormatAndRoundTrip(t *testing.T) {
	if packed, err := packAPLib([]byte("A")); err != nil || !bytes.Equal(packed, []byte{'A', 0xc0, 0}) {
		t.Fatalf("single byte format: %x, %v", packed, err)
	}
	random := make([]byte, 8192)
	if _, err := rand.New(rand.NewSource(42)).Read(random); err != nil {
		t.Fatal(err)
	}
	cases := [][]byte{
		{0}, []byte("ABC"), bytes.Repeat([]byte("A"), 4096),
		bytes.Repeat([]byte("ABCD"), 16384), bytes.Repeat([]byte{0}, 2000),
		random,
	}
	// A distant repeated sequence crosses both offset bonus thresholds.
	distant := make([]byte, 33000)
	copy(distant, random)
	binary.LittleEndian.PutUint64(distant[32000:], 0x1122334455667788)
	copy(distant[32900:], distant[:100])
	cases = append(cases, distant)
	for _, input := range cases {
		packed, err := packAPLib(input)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := referenceDepack(packed, input)
		if err != nil {
			t.Fatalf("input length %d, packed length %d: %v", len(input), len(packed), err)
		}
		if !bytes.Equal(decoded, input) {
			at := 0
			for at < len(input) && input[at] == decoded[at] {
				at++
			}
			t.Fatalf("round trip failed for %d bytes at %d: got %x want %x", len(input), at, decoded[at:min(at+16, len(decoded))], input[at:min(at+16, len(input))])
		}
	}
}

func TestPackAPLibCompressesRepetition(t *testing.T) {
	input := bytes.Repeat([]byte("structured payload with repeated content\n"), 1000)
	packed, err := packAPLib(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(packed) >= len(input)/2 {
		t.Fatalf("packed length %d did not compress repeated input of %d bytes", len(packed), len(input))
	}
}
