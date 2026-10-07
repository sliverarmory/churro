package wire

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Values were produced by the C implementation linked with the checked-in
// poly_seed.h. They catch rotation, word-order, and counter-order regressions.
func TestCReferenceVectors(t *testing.T) {
	if got, want := Maru("kernel32.dll", 0x0123456789abcdef, DefaultPoly), uint64(0xb1d0e524f687a839); got != want {
		t.Fatalf("Maru = %016x, want %016x", got, want)
	}
	var key, ctr [16]byte
	for i := range key {
		key[i] = byte(i)
		ctr[i] = byte(0xf0 + i)
	}
	data := make([]byte, 37)
	for i := range data {
		data[i] = byte(i)
	}
	Crypt(data, &key, &ctr, DefaultPoly)
	if got, want := hex.EncodeToString(data), "f09fabf1fa514fc6c8997bccd4975eb1457cb0e25cda6d3d8745efcd499df3e5936f72ebb5"; got != want {
		t.Fatalf("Crypt = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(ctr[:]), "f0f1f2f3f4f5f6f7f8f9fafbfcfdff02"; got != want {
		t.Fatalf("counter = %s, want %s", got, want)
	}
	decryptCTR, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	copy(ctr[:], decryptCTR)
	Crypt(data, &key, &ctr, DefaultPoly)
	for i, b := range data {
		if b != byte(i) {
			t.Fatalf("decryption differs at byte %d", i)
		}
	}
	if bytes.Equal(data, make([]byte, len(data))) {
		t.Fatal("decrypted data unexpectedly all zero")
	}
}
