package churro

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestFormatLoaderBinaryOwnsBytes(t *testing.T) {
	raw := []byte{0x00, 0x41, 0xff}
	got, err := formatLoader(raw, FormatBinary)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("binary output = %x, want %x", got, raw)
	}
	got[0] = 0x7f
	if raw[0] != 0x00 {
		t.Fatal("binary output aliases the input")
	}
}

func TestFormatLoaderBase64RoundTrip(t *testing.T) {
	raw := []byte{0x00, 0x41, 0xff, 0x20}
	encoded, err := formatLoader(raw, FormatBase64)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, raw) {
		t.Fatalf("decoded output = %x, want %x", decoded, raw)
	}
}

func TestFormatLoaderTextRepresentations(t *testing.T) {
	raw := []byte{0x00, 0x41, 0xff}
	tests := []struct {
		name   string
		format Format
		want   []string
	}{
		{"C", FormatC, []string{"unsigned char buf[]", `"\x00\x41\xff"`}},
		{"Ruby", FormatRuby, []string{`buf = [`, `0x00, 0x41, 0xff`, `].pack("C*")`}},
		{"Python", FormatPython, []string{`buf = b""`, `buf += b"\x00\x41\xff"`}},
		{"PowerShell", FormatPowerShell, []string{`[Byte[]] $buf = 0x00,0x41,0xff`}},
		{"CSharp", FormatCSharp, []string{`byte[] my_buf = new byte[3]`, `0x00,0x41,0xff`}},
		{"Hex", FormatHex, []string{`\x00\x41\xff`}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := formatLoader(raw, test.format)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range test.want {
				if !strings.Contains(string(got), want) {
					t.Fatalf("output %q does not contain %q", got, want)
				}
			}
		})
	}
}

func TestFormatLoaderUUIDByteOrderAndPadding(t *testing.T) {
	raw := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11,
	}
	got, err := formatLoader(raw, FormatUUID)
	if err != nil {
		t.Fatal(err)
	}
	want := "03020100-0504-0706-0809-0a0b0c0d0e0f\n00001110-0000-0000-0000-000000000000\n"
	if string(got) != want {
		t.Fatalf("UUID output = %q, want %q", got, want)
	}
}

func TestFormatLoaderRejectsUnknownFormat(t *testing.T) {
	if _, err := formatLoader([]byte{1}, FormatUUID+1); err == nil {
		t.Fatal("unknown format accepted")
	}
}
