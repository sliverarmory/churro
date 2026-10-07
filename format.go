package churro

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
)

const hexDigits = "0123456789abcdef"

// formatLoader renders raw shellcode in the representation requested by the
// caller. The binary result is copied so every Result owns its returned bytes.
func formatLoader(raw []byte, format Format) ([]byte, error) {
	switch format {
	case FormatBinary:
		return append([]byte(nil), raw...), nil
	case FormatBase64:
		out := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
		base64.StdEncoding.Encode(out, raw)
		return out, nil
	case FormatC:
		return formatC(raw), nil
	case FormatRuby:
		return formatRuby(raw), nil
	case FormatPython:
		return formatPython(raw), nil
	case FormatPowerShell:
		return formatPowerShell(raw), nil
	case FormatCSharp:
		return formatCSharp(raw), nil
	case FormatHex:
		return formatHex(raw), nil
	case FormatUUID:
		return formatUUID(raw), nil
	default:
		return nil, fmt.Errorf("churro: unsupported output format %d", format)
	}
}

func formatC(raw []byte) []byte {
	var out bytes.Buffer
	out.WriteString("unsigned char buf[] =\n")
	for start := 0; start < len(raw); start += 16 {
		end := min(start+16, len(raw))
		out.WriteByte('"')
		for _, value := range raw[start:end] {
			writeEscapedByte(&out, value)
		}
		out.WriteString("\"\n")
	}
	if len(raw) == 0 {
		out.WriteString("\"\"\n")
	}
	out.WriteString(";\n")
	return out.Bytes()
}

func formatRuby(raw []byte) []byte {
	var out bytes.Buffer
	out.WriteString("buf = [\n")
	for i, value := range raw {
		if i%16 == 0 {
			out.WriteString("  ")
		}
		writeHexLiteral(&out, value)
		if i+1 < len(raw) {
			out.WriteByte(',')
		}
		if i%16 == 15 || i+1 == len(raw) {
			out.WriteByte('\n')
		} else {
			out.WriteByte(' ')
		}
	}
	out.WriteString("].pack(\"C*\")\n")
	return out.Bytes()
}

func formatPython(raw []byte) []byte {
	var out bytes.Buffer
	out.WriteString("buf = b\"\"\n")
	for start := 0; start < len(raw); start += 16 {
		end := min(start+16, len(raw))
		out.WriteString("buf += b\"")
		for _, value := range raw[start:end] {
			writeEscapedByte(&out, value)
		}
		out.WriteString("\"\n")
	}
	return out.Bytes()
}

func formatPowerShell(raw []byte) []byte {
	var out bytes.Buffer
	out.WriteString("[Byte[]] $buf = ")
	for i, value := range raw {
		if i != 0 {
			out.WriteByte(',')
		}
		writeHexLiteral(&out, value)
	}
	out.WriteByte('\n')
	return out.Bytes()
}

func formatCSharp(raw []byte) []byte {
	var out bytes.Buffer
	out.WriteString("byte[] my_buf = new byte[")
	out.WriteString(strconv.Itoa(len(raw)))
	out.WriteString("] {\n")
	for i, value := range raw {
		if i%16 == 0 {
			out.WriteString("  ")
		}
		writeHexLiteral(&out, value)
		if i+1 < len(raw) {
			out.WriteByte(',')
		}
		if i%16 == 15 || i+1 == len(raw) {
			out.WriteByte('\n')
		}
	}
	out.WriteString("};\n")
	return out.Bytes()
}

func formatHex(raw []byte) []byte {
	var out bytes.Buffer
	for _, value := range raw {
		writeEscapedByte(&out, value)
	}
	return out.Bytes()
}

// UUID output follows Windows GUID byte order for the first three fields.
// The final block is zero-padded to 16 bytes, matching Fritter's UUID format.
func formatUUID(raw []byte) []byte {
	var out bytes.Buffer
	for start := 0; start < len(raw); start += 16 {
		var block [16]byte
		copy(block[:], raw[start:min(start+16, len(raw))])
		for i, position := range [...]int{3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15} {
			switch i {
			case 4, 6, 8, 10:
				out.WriteByte('-')
			}
			writeHexByte(&out, block[position])
		}
		out.WriteByte('\n')
	}
	return out.Bytes()
}

func writeEscapedByte(out *bytes.Buffer, value byte) {
	out.WriteString("\\x")
	writeHexByte(out, value)
}

func writeHexLiteral(out *bytes.Buffer, value byte) {
	out.WriteString("0x")
	writeHexByte(out, value)
}

func writeHexByte(out *bytes.Buffer, value byte) {
	out.WriteByte(hexDigits[value>>4])
	out.WriteByte(hexDigits[value&0x0f])
}
