// Command table2json converts exe2h's section and reference tables to the
// metadata format consumed by Churro's Go loader preparation code.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
)

type function struct {
	Offset     uint32 `json:"offset"`
	Size       uint32 `json:"size"`
	SinglePage bool   `json:"single_page"`
	Name       string `json:"name"`
}

type reference struct {
	SourceOffset       uint32 `json:"src_blob_off"`
	InstructionLength  uint16 `json:"inst_length"`
	DisplacementOffset uint16 `json:"disp_offset"`
	SourceFunction     uint16 `json:"src_fn"`
	TargetFunction     uint16 `json:"target_fn"`
}

type metadata struct {
	Functions  []function  `json:"functions"`
	References []reference `json:"references"`
}

var (
	fnCountPattern  = regexp.MustCompile(`(?m)^#define [A-Z0-9_]+_FN_COUNT ([0-9]+)$`)
	refCountPattern = regexp.MustCompile(`(?m)^#define [A-Z0-9_]+_REF_COUNT ([0-9]+)$`)
	fnEntryPattern  = regexp.MustCompile(`(?m)^\s*\{\s*(0x[[:xdigit:]]+|[0-9]+),\s*(0x[[:xdigit:]]+|[0-9]+),\s*([01]),\s*\{0,0,0\},\s*"([.A-Za-z0-9_]+)"\s*\},$`)
	refEntryPattern = regexp.MustCompile(`(?m)^\s*\{\s*(0x[[:xdigit:]]+|[0-9]+),\s*([0-9]+),\s*([0-9]+),\s*([0-9]+),\s*([0-9]+)\s*\},?$`)
)

func main() {
	if len(os.Args) != 4 {
		fatalf("usage: table2json fn_table.h ref_table.h output.json")
	}
	fnHeader, err := os.ReadFile(os.Args[1])
	if err != nil {
		fatalf("read function table: %v", err)
	}
	refHeader, err := os.ReadFile(os.Args[2])
	if err != nil {
		fatalf("read reference table: %v", err)
	}
	parsed, err := parseTables(fnHeader, refHeader)
	if err != nil {
		fatalf("parse loader tables: %v", err)
	}
	output, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		fatalf("marshal loader metadata: %v", err)
	}
	output = append(output, '\n')
	if err := os.WriteFile(os.Args[3], output, 0o644); err != nil {
		fatalf("write loader metadata: %v", err)
	}
}

func parseTables(fnHeader, refHeader []byte) (metadata, error) {
	fnCount, err := parseCount(fnCountPattern, fnHeader)
	if err != nil {
		return metadata{}, fmt.Errorf("function count: %w", err)
	}
	refCount, err := parseCount(refCountPattern, refHeader)
	if err != nil {
		return metadata{}, fmt.Errorf("reference count: %w", err)
	}
	fnRows := fnEntryPattern.FindAllSubmatch(fnHeader, -1)
	refRows := refEntryPattern.FindAllSubmatch(refHeader, -1)
	if fnCount == 0 || len(fnRows) != fnCount {
		return metadata{}, fmt.Errorf("function count %d does not match %d rows", fnCount, len(fnRows))
	}
	if len(refRows) != refCount+1 {
		return metadata{}, fmt.Errorf("reference count %d does not match %d rows including sentinel", refCount, len(refRows))
	}
	result := metadata{Functions: make([]function, 0, fnCount), References: make([]reference, 0, refCount)}
	for i, row := range fnRows {
		offset, err := parseUint(row[1], 32)
		if err != nil {
			return metadata{}, fmt.Errorf("function %d offset: %w", i, err)
		}
		size, err := parseUint(row[2], 32)
		if err != nil || size == 0 {
			return metadata{}, fmt.Errorf("function %d has invalid size", i)
		}
		result.Functions = append(result.Functions, function{
			Offset: uint32(offset), Size: uint32(size),
			SinglePage: row[3][0] == '1', Name: string(row[4]),
		})
	}
	for i, row := range refRows {
		values := make([]uint64, 5)
		for j := 0; j < len(values); j++ {
			bits := 16
			if j == 0 {
				bits = 32
			}
			values[j], err = parseUint(row[j+1], bits)
			if err != nil {
				return metadata{}, fmt.Errorf("reference %d field %d: %w", i, j, err)
			}
		}
		if i == refCount {
			for _, value := range values {
				if value != 0 {
					return metadata{}, errors.New("reference table sentinel is not zero")
				}
			}
			break
		}
		if int(values[3]) >= fnCount || int(values[4]) >= fnCount {
			return metadata{}, fmt.Errorf("reference %d has invalid function index", i)
		}
		if values[1] == 0 || values[2]+4 > values[1] {
			return metadata{}, fmt.Errorf("reference %d has invalid displacement", i)
		}
		result.References = append(result.References, reference{
			SourceOffset: uint32(values[0]), InstructionLength: uint16(values[1]),
			DisplacementOffset: uint16(values[2]), SourceFunction: uint16(values[3]),
			TargetFunction: uint16(values[4]),
		})
	}
	return result, nil
}

func parseCount(pattern *regexp.Regexp, header []byte) (int, error) {
	all := pattern.FindAllSubmatch(header, -1)
	if len(all) != 1 {
		return 0, errors.New("expected exactly one count definition")
	}
	count, err := strconv.Atoi(string(all[0][1]))
	if err != nil || count < 0 || count > 65535 {
		return 0, errors.New("count out of range")
	}
	return count, nil
}

func parseUint(literal []byte, bits int) (uint64, error) {
	return strconv.ParseUint(string(literal), 0, bits)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
