package churro

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
)

const hexDigits = "0123456789abcdef"

// formatLoader renders raw shellcode in the representation requested by the
// caller. The binary result is copied so every Result owns its returned bytes.
func formatLoader(raw []byte, format Format) ([]byte, error) {
	return formatLoaderContext(context.Background(), raw, format)
}

func formatLoaderContext(ctx context.Context, raw []byte, format Format) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch format {
	case FormatBinary:
		out := make([]byte, len(raw))
		for start := 0; start < len(raw); start += 64 << 10 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			end := min(start+(64<<10), len(raw))
			copy(out[start:end], raw[start:end])
		}
		return out, ctx.Err()
	case FormatBase64:
		out := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
		for start := 0; start < len(raw); start += 48 << 10 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			end := min(start+(48<<10), len(raw))
			base64.StdEncoding.Encode(out[base64.StdEncoding.EncodedLen(start):], raw[start:end])
		}
		return out, ctx.Err()
	case FormatC:
		return formatC(ctx, raw)
	case FormatRuby:
		return formatRuby(ctx, raw)
	case FormatPython:
		return formatPython(ctx, raw)
	case FormatPowerShell:
		return formatPowerShell(ctx, raw)
	case FormatCSharp:
		return formatCSharp(ctx, raw)
	case FormatHex:
		return formatHex(ctx, raw)
	case FormatUUID:
		return formatUUID(ctx, raw)
	default:
		return nil, fmt.Errorf("churro: unsupported output format %d", format)
	}
}

func formatC(ctx context.Context, raw []byte) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString("unsigned char buf[] =\n")
	for start := 0; start < len(raw); start += 16 {
		if err := formatCheckpoint(ctx, start); err != nil {
			return nil, err
		}
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
	return out.Bytes(), ctx.Err()
}

func formatRuby(ctx context.Context, raw []byte) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString("buf = [\n")
	for i, value := range raw {
		if err := formatCheckpoint(ctx, i); err != nil {
			return nil, err
		}
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
	return out.Bytes(), ctx.Err()
}

func formatPython(ctx context.Context, raw []byte) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString("buf = b\"\"\n")
	for start := 0; start < len(raw); start += 16 {
		if err := formatCheckpoint(ctx, start); err != nil {
			return nil, err
		}
		end := min(start+16, len(raw))
		out.WriteString("buf += b\"")
		for _, value := range raw[start:end] {
			writeEscapedByte(&out, value)
		}
		out.WriteString("\"\n")
	}
	return out.Bytes(), ctx.Err()
}

func formatPowerShell(ctx context.Context, raw []byte) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString("[Byte[]] $buf = ")
	for i, value := range raw {
		if err := formatCheckpoint(ctx, i); err != nil {
			return nil, err
		}
		if i != 0 {
			out.WriteByte(',')
		}
		writeHexLiteral(&out, value)
	}
	out.WriteByte('\n')
	return out.Bytes(), ctx.Err()
}

func formatCSharp(ctx context.Context, raw []byte) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString("byte[] my_buf = new byte[")
	out.WriteString(strconv.Itoa(len(raw)))
	out.WriteString("] {\n")
	for i, value := range raw {
		if err := formatCheckpoint(ctx, i); err != nil {
			return nil, err
		}
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
	return out.Bytes(), ctx.Err()
}

func formatHex(ctx context.Context, raw []byte) ([]byte, error) {
	var out bytes.Buffer
	for i, value := range raw {
		if err := formatCheckpoint(ctx, i); err != nil {
			return nil, err
		}
		writeEscapedByte(&out, value)
	}
	return out.Bytes(), ctx.Err()
}

// UUID output follows Windows GUID byte order for the first three fields.
// The final block is zero-padded to 16 bytes, matching Fritter's UUID format.
func formatUUID(ctx context.Context, raw []byte) ([]byte, error) {
	var out bytes.Buffer
	for start := 0; start < len(raw); start += 16 {
		if err := formatCheckpoint(ctx, start); err != nil {
			return nil, err
		}
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
	return out.Bytes(), ctx.Err()
}

func formatCheckpoint(ctx context.Context, offset int) error {
	if offset&4095 == 0 {
		return ctx.Err()
	}
	return nil
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
