package wire

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

type peInfo struct {
	moduleType int
	runtime    string
}

type peSection struct {
	virtualAddress uint32
	virtualSize    uint32
	rawAddress     uint32
	rawSize        uint32
}

type peImage struct {
	data          []byte
	sections      []peSection
	machine       uint16
	magic         uint16
	character     uint16
	sizeOfHeaders uint32
	exportRVA     uint32
	comRVA        uint32
}

func inspectPE(image []byte, export string) (peInfo, error) {
	file, err := parsePE(image)
	if err != nil {
		return peInfo{}, err
	}
	dll := file.character&0x2000 != 0 // IMAGE_FILE_DLL
	managed := file.comRVA != 0
	if managed && file.exportRVA != 0 {
		return peInfo{}, fmt.Errorf("mixed native and managed assemblies are unsupported")
	}
	if !managed && (file.machine != 0x8664 || file.magic != 0x20b) {
		return peInfo{}, fmt.Errorf("native PE payload must be x64")
	}
	info := peInfo{}
	if managed {
		if dll {
			info.moduleType = ModuleDotNetDLL
		} else {
			info.moduleType = ModuleDotNetExecutable
		}
		info.runtime = file.runtimeFromMetadata()
	} else if dll {
		info.moduleType = ModuleNativeDLL
	} else {
		info.moduleType = ModuleNativeExecutable
	}
	if export != "" && info.moduleType == ModuleNativeDLL {
		found, err := file.hasNamedExport(export)
		if err != nil {
			return peInfo{}, err
		}
		if !found {
			return peInfo{}, fmt.Errorf("native DLL does not export %q", export)
		}
	}
	return info, nil
}

func parsePE(image []byte) (peImage, error) {
	bad := func() (peImage, error) { return peImage{}, fmt.Errorf("invalid PE payload") }
	if len(image) < 0x40 || string(image[:2]) != "MZ" {
		return bad()
	}
	nt := uint64(binary.LittleEndian.Uint32(image[0x3c:]))
	if nt > uint64(len(image)) || uint64(len(image))-nt < 24 || string(image[nt:nt+4]) != "PE\x00\x00" {
		return bad()
	}
	fh := image[nt+4 : nt+24]
	file := peImage{
		data:      image,
		machine:   binary.LittleEndian.Uint16(fh[0:]),
		character: binary.LittleEndian.Uint16(fh[18:]),
	}
	sectionCount := int(binary.LittleEndian.Uint16(fh[2:]))
	optionalSize := uint64(binary.LittleEndian.Uint16(fh[16:]))
	if sectionCount == 0 || sectionCount > 96 || optionalSize < 2 || nt+24+optionalSize > uint64(len(image)) {
		return bad()
	}
	opt := image[nt+24 : nt+24+optionalSize]
	file.magic = binary.LittleEndian.Uint16(opt)
	var directoryStart, numberOfDirectories int
	switch file.magic {
	case 0x10b: // PE32, commonly used for AnyCPU managed assemblies.
		directoryStart, numberOfDirectories = 96, 92
	case 0x20b: // PE32+.
		directoryStart, numberOfDirectories = 112, 108
	default:
		return bad()
	}
	if len(opt) < directoryStart || len(opt) < numberOfDirectories+4 {
		return bad()
	}
	file.sizeOfHeaders = binary.LittleEndian.Uint32(opt[60:])
	nDirs := binary.LittleEndian.Uint32(opt[numberOfDirectories:])
	if nDirs > 0 && len(opt) >= directoryStart+8 {
		file.exportRVA = binary.LittleEndian.Uint32(opt[directoryStart:])
	}
	if nDirs > 14 && len(opt) >= directoryStart+15*8 {
		file.comRVA = binary.LittleEndian.Uint32(opt[directoryStart+14*8:])
	}
	sectionsOff := nt + 24 + optionalSize
	if sectionsOff+uint64(sectionCount)*40 > uint64(len(image)) {
		return bad()
	}
	file.sections = make([]peSection, sectionCount)
	for i := range file.sections {
		s := image[sectionsOff+uint64(i)*40:]
		file.sections[i] = peSection{
			virtualSize:    binary.LittleEndian.Uint32(s[8:]),
			virtualAddress: binary.LittleEndian.Uint32(s[12:]),
			rawSize:        binary.LittleEndian.Uint32(s[16:]),
			rawAddress:     binary.LittleEndian.Uint32(s[20:]),
		}
	}
	return file, nil
}

func (file peImage) runtimeFromMetadata() string {
	const fallback = "v4.0.30319"
	comOff, ok := file.rvaOffset(file.comRVA, 16)
	if !ok {
		return fallback
	}
	metadataRVA := binary.LittleEndian.Uint32(file.data[comOff+8:])
	metadataOff, ok := file.rvaOffset(metadataRVA, 16)
	if !ok || string(file.data[metadataOff:metadataOff+4]) != "BSJB" {
		return fallback
	}
	versionLen := binary.LittleEndian.Uint32(file.data[metadataOff+12:])
	if versionLen == 0 || versionLen > 255 || uint64(metadataOff)+16+uint64(versionLen) > uint64(len(file.data)) {
		return fallback
	}
	version := strings.TrimRight(string(file.data[metadataOff+16:metadataOff+16+int(versionLen)]), "\x00")
	if version == "" || len(version) > 31 {
		return fallback
	}
	return version
}

func (file peImage) hasNamedExport(name string) (bool, error) {
	if file.exportRVA == 0 {
		return false, nil
	}
	exportOff, ok := file.rvaOffset(file.exportRVA, 40)
	if !ok {
		return false, fmt.Errorf("invalid PE export directory")
	}
	count := binary.LittleEndian.Uint32(file.data[exportOff+24:])
	namesRVA := binary.LittleEndian.Uint32(file.data[exportOff+32:])
	if count == 0 {
		return false, nil
	}
	if count > uint32(len(file.data)/4) {
		return false, fmt.Errorf("invalid PE export name count")
	}
	namesOff, ok := file.rvaOffset(namesRVA, uint64(count)*4)
	if !ok {
		return false, fmt.Errorf("invalid PE export name array")
	}
	for i := uint32(0); i < count; i++ {
		rva := binary.LittleEndian.Uint32(file.data[namesOff+int(i)*4:])
		off, ok := file.rvaOffset(rva, 1)
		if !ok {
			return false, fmt.Errorf("invalid PE export name RVA")
		}
		end := bytes.IndexByte(file.data[off:], 0)
		if end < 0 {
			return false, fmt.Errorf("unterminated PE export name")
		}
		if end == len(name) && string(file.data[off:off+end]) == name {
			return true, nil
		}
	}
	return false, nil
}

func (file peImage) rvaOffset(rva uint32, need uint64) (int, bool) {
	var off uint64
	if rva < file.sizeOfHeaders {
		off = uint64(rva)
	} else {
		found := false
		for _, section := range file.sections {
			span := max(section.virtualSize, section.rawSize)
			if rva < section.virtualAddress || uint64(rva)-uint64(section.virtualAddress) >= uint64(span) {
				continue
			}
			delta := rva - section.virtualAddress
			if delta >= section.rawSize {
				return 0, false
			}
			off = uint64(section.rawAddress) + uint64(delta)
			found = true
			break
		}
		if !found {
			return 0, false
		}
	}
	if off > uint64(len(file.data)) || need > uint64(len(file.data))-off {
		return 0, false
	}
	return int(off), true
}
