package wire

import (
	"encoding/binary"
	"math/bits"
)

// Poly is the subset of poly_seed.h shared by the generator and the loader.
// Changing it without rebuilding the loader blobs makes generated output fail.
type Poly struct {
	CipherRotations [6]uint32
	CipherRounds    uint32
	HashRotA        uint32
	HashRotB        uint32
	HashRounds      uint32
}

// DefaultPoly matches the loader blobs in internal/assets (build seed
// 0xDA44B96C). Keep this in step with poly_seed.h when rebuilding those blobs.
var DefaultPoly = Poly{
	CipherRotations: [6]uint32{4, 4, 16, 23, 22, 11},
	CipherRounds:    20,
	HashRotA:        3,
	HashRotB:        13,
	HashRounds:      27,
}

func (p Poly) normalized() Poly {
	if p.CipherRounds == 0 && p.HashRounds == 0 {
		return DefaultPoly
	}
	return p
}

// Maru implements the loader's 64-bit, length-padded API/string hash.
// The input is interpreted as a C string, limited to 64 bytes.
func Maru(input string, iv uint64, poly Poly) uint64 {
	poly = poly.normalized()
	b := []byte(input)
	if i := indexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	if len(b) > 64 {
		b = b[:64]
	}
	length := len(b)
	h := iv
	for len(b) >= 16 {
		h ^= hashCipher(b[:16], h, poly)
		b = b[16:]
	}
	var block [16]byte
	copy(block[:], b)
	block[len(b)] = 0x80
	if len(b) >= 12 {
		h ^= hashCipher(block[:], h, poly)
		block = [16]byte{}
	}
	binary.LittleEndian.PutUint32(block[12:], uint32(length*8))
	h ^= hashCipher(block[:], h, poly)
	return h
}

func hashCipher(key []byte, input uint64, poly Poly) uint64 {
	k := [4]uint32{
		binary.LittleEndian.Uint32(key[0:4]),
		binary.LittleEndian.Uint32(key[4:8]),
		binary.LittleEndian.Uint32(key[8:12]),
		binary.LittleEndian.Uint32(key[12:16]),
	}
	w0, w1 := uint32(input), uint32(input>>32)
	for i := uint32(0); i < poly.HashRounds; i++ {
		w0 = (bits.RotateLeft32(w0, -int(poly.HashRotA)) + w1) ^ k[0]
		w1 = bits.RotateLeft32(w1, int(poly.HashRotB)) ^ w0
		t := k[3]
		k[3] = (bits.RotateLeft32(k[1], -int(poly.HashRotA)) + k[0]) ^ i
		k[0] = bits.RotateLeft32(k[0], int(poly.HashRotB)) ^ k[3]
		k[1], k[2] = k[2], t
	}
	return uint64(w1)<<32 | uint64(w0)
}

// Crypt applies Fritter's ARX-CTR stream cipher. It changes data and counter
// in place; callers should keep an unmodified copy of the initial counter in
// the serialized FRITTER_CRYPT structure.
func Crypt(data []byte, key *[16]byte, counter *[16]byte, poly Poly) {
	poly = poly.normalized()
	var stream [16]byte
	for len(data) > 0 {
		stream = *counter
		blockCipher(&stream, key, poly)
		n := min(len(data), len(stream))
		for i := 0; i < n; i++ {
			data[i] ^= stream[i]
		}
		data = data[n:]
		for i := len(counter) - 1; i >= 0; i-- {
			counter[i]++
			if counter[i] != 0 {
				break
			}
		}
	}
}

func blockCipher(block *[16]byte, key *[16]byte, poly Poly) {
	var w, k [4]uint32
	for i := range w {
		w[i] = binary.LittleEndian.Uint32(block[i*4:])
		k[i] = binary.LittleEndian.Uint32(key[i*4:])
		w[i] ^= k[i]
	}
	r := poly.CipherRotations
	for i := uint32(0); i < poly.CipherRounds; i++ {
		w[0] += w[1]
		w[1] = bits.RotateLeft32(w[1], int(r[0])) ^ w[0]
		w[2] += w[3]
		w[3] = bits.RotateLeft32(w[3], int(r[1])) ^ w[2]
		w[2] += w[1]
		w[0] = bits.RotateLeft32(w[0], -int(r[2])) + w[3]
		w[3] = bits.RotateLeft32(w[3], int(r[3])) ^ w[0]
		w[1] = bits.RotateLeft32(w[1], -int(r[4])) ^ w[2]
		w[2] = bits.RotateLeft32(w[2], int(r[5]))
	}
	for i := range w {
		binary.LittleEndian.PutUint32(block[i*4:], w[i]^k[i])
	}
}

func indexByte(b []byte, needle byte) int {
	for i, v := range b {
		if v == needle {
			return i
		}
	}
	return -1
}
