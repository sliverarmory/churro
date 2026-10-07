package wire

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestEmbeddedScriptLayout(t *testing.T) {
	payload := []byte(`WScript.Echo("hello")`)
	instance, staged, name, err := Build(Config{
		Payload: payload, ModuleType: ModuleJScript,
		Entropy: 1, Exit: 1, Headers: 1, UTF8: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if staged != nil || name != "" {
		t.Fatalf("unexpected staging output: len=%d name=%q", len(staged), name)
	}
	if int(u32(instance, 0)) != len(instance) || u32(instance, 2152) != 1 || u32(instance, 572) != 61 {
		t.Fatal("instance header does not match C wire layout")
	}
	if u32(instance, 1368) != 1 || u32(instance, 564) != 1 || u32(instance, 560) != 1 {
		t.Fatal("typed invocation flags missing")
	}
	modLen := int(u64(instance, 3232))
	if len(instance) < instanceSize+modLen || len(instance) > instanceSize+modLen+255 {
		t.Fatalf("instance length %d differs from C allocation rule", len(instance))
	}
	mod := instance[instanceModOff : instanceModOff+modLen]
	if u32(mod, 0) != ModuleJScript || u32(mod, 8) != 1 || u32(mod, 1320) != uint32(len(payload)) || u32(mod, 1324) != uint32(len(payload)) {
		t.Fatal("module header does not match C wire layout")
	}
	if !bytes.Equal(mod[moduleDataOffset:moduleDataOffset+len(payload)], payload) {
		t.Fatal("payload missing from module")
	}
	if u64(instance, 48) != Maru("LoadLibraryA", 0, DefaultPoly)^Maru("kernel32.dll", 0, DefaultPoly) {
		t.Fatal("API hash slot 0 does not match the pinned API")
	}
	if got := cString(instance[576:832]); got != defaultDLLNames {
		t.Fatalf("default DLL preload list changed: %q", got)
	}
	if string(instance[1380:1391]) != "wscript.exe" {
		t.Fatal("script host strings missing")
	}
}

func TestCustomAPIImportWireLayoutAndPreload(t *testing.T) {
	imports := append([]APIImport(nil), DefaultAPIImports...)
	imports = append(imports, APIImport{Module: "advapi32.dll", Name: "GetUserNameA"})
	instance, _, _, err := Build(Config{
		Payload: []byte("WScript.Echo 1"), ModuleType: ModuleVBScript,
		Entropy: 1, APIImports: imports,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := u32(instance, 572); got != 62 {
		t.Fatalf("API count = %d, want 62", got)
	}
	if got := u64(instance, 48+61*8); got != Maru("GetUserNameA", 0, DefaultPoly)^Maru("advapi32.dll", 0, DefaultPoly) {
		t.Fatalf("custom API hash = %016x", got)
	}
	if got := cString(instance[576:832]); got != defaultDLLNames+";advapi32.dll" {
		t.Fatalf("DLL preload list = %q", got)
	}
	if instance[576+len(defaultDLLNames)+len(";advapi32.dll")+1] != 0 {
		t.Fatal("DLL preload list lacks a second NUL terminator")
	}
	imports[0].Module = "ntdll.dll"
	if _, _, _, err := Build(Config{Payload: []byte("WScript.Echo 1"), ModuleType: ModuleVBScript, APIImports: imports}); err == nil || !strings.Contains(err.Error(), "slot 0") {
		t.Fatalf("wrong LoadLibraryA module result = %v", err)
	}
}

func TestCustomAPIImportPreloadBounds(t *testing.T) {
	imports := []APIImport{{Module: "kernel32.dll", Name: "LoadLibraryA"}}
	for i := 0; i < 4; i++ {
		module := strings.Repeat(string(rune('a'+i)), 59) + ".dll"
		imports = append(imports, APIImport{Module: module, Name: "Export"})
	}
	if _, err := DLLNamesForAPIImports(imports); err == nil || !strings.Contains(err.Error(), "254 bytes") {
		t.Fatalf("oversize preload list result = %v", err)
	}
	imports = imports[:1]
	imports = append(imports, APIImport{Module: "Advapi32.dll", Name: "GetUserNameA"})
	if _, err := DLLNamesForAPIImports(imports); err == nil || !strings.Contains(err.Error(), "invalid DLL name") {
		t.Fatalf("mixed-case DLL name result = %v", err)
	}
	imports[1].Module = "my_module.dll"
	if _, err := DLLNamesForAPIImports(imports); err == nil || !strings.Contains(err.Error(), "invalid DLL name") {
		t.Fatalf("underscore DLL name result = %v", err)
	}
}

func TestEncryptedStagingRoundTrip(t *testing.T) {
	payload := []byte(`WScript.Echo("staged")`)
	instance, staged, name, err := Build(Config{
		Payload: payload, ModuleType: ModuleVBScript, Entropy: 3,
		Exit: 1, Headers: 1, UTF8: true,
		StagingURL: "https://example.test/stage/", ModuleName: "ABCDEFGH",
	})
	if err != nil {
		t.Fatal(err)
	}
	if name != "ABCDEFGH" || len(instance) < instanceSize || len(staged) < moduleSize+len(payload) {
		t.Fatalf("unexpected staging output: name=%q instance=%d module=%d", name, len(instance), len(staged))
	}
	var key, ctr [16]byte
	copy(key[:], instance[4:20])
	copy(ctr[:], instance[20:36])
	plainInstance := bytes.Clone(instance)
	Crypt(plainInstance[instanceCryptOff:], &key, &ctr, DefaultPoly)
	if u32(plainInstance, 2152) != 2 || !strings.HasPrefix(string(plainInstance[2156:2412]), "https://example.test/stage/ABCDEFGH\x00") {
		t.Fatal("staging URL or mode does not decrypt")
	}
	sig := string(plainInstance[2932:2940])
	mac := Maru(sig, u64(plainInstance, 40), DefaultPoly)
	if u64(plainInstance, 3192) != mac {
		t.Fatal("instance MAC does not match C derivation")
	}
	copy(key[:], plainInstance[3200:3216])
	copy(ctr[:], plainInstance[3216:3232])
	plainModule := bytes.Clone(staged)
	Crypt(plainModule, &key, &ctr, DefaultPoly)
	if u32(plainModule, 0) != ModuleVBScript || u64(plainModule, 1312) != mac || !bytes.Equal(plainModule[moduleDataOffset:moduleDataOffset+len(payload)], payload) {
		t.Fatal("staged module does not decrypt to expected wire contents")
	}
}

func TestNativeDLLExportValidation(t *testing.T) {
	image := syntheticPE(true, false, "HelloWorld")
	_, _, _, err := Build(Config{Payload: image, ModuleType: ModuleNativeDLL, Method: "HelloWorld", Entropy: 1})
	if err != nil {
		t.Fatalf("valid x64 DLL: %v", err)
	}
	_, _, _, err = Build(Config{Payload: image, ModuleType: ModuleNativeDLL, Method: "helloworld", Entropy: 1})
	if err == nil || !strings.Contains(err.Error(), "does not export") {
		t.Fatalf("case-sensitive export lookup error = %v", err)
	}
	_, _, _, err = Build(Config{Payload: image, ModuleType: ModuleNativeExecutable, Entropy: 1})
	if err == nil || !strings.Contains(err.Error(), "expected") {
		t.Fatalf("DLL/EXE mismatch error = %v", err)
	}
	image[0x84] = 0x4c // IMAGE_FILE_MACHINE_I386
	image[0x85] = 0x01
	_, _, _, err = Build(Config{Payload: image, ModuleType: ModuleNativeDLL, Entropy: 1})
	if err == nil || !strings.Contains(err.Error(), "x64") {
		t.Fatalf("x86 native DLL error = %v", err)
	}
}

func TestNativeArgumentsAndUnicodeWireLayout(t *testing.T) {
	dll := syntheticPE(true, false, "HelloWorld")
	instance, _, _, err := Build(Config{
		Payload: dll, ModuleType: ModuleNativeDLL, Method: "HelloWorld",
		Arguments: "hello world", Unicode: true, Entropy: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	mod := instance[instanceModOff:]
	if got := cString(mod[1036:1292]); got != "hello world" {
		t.Fatalf("DLL argument = %q", got)
	}
	if got := u32(mod, 1296); got != 1 {
		t.Fatalf("DLL Unicode flag = %d", got)
	}
	_, _, _, err = Build(Config{Payload: dll, ModuleType: ModuleNativeDLL, Arguments: "hello", Entropy: 1})
	if err == nil || !strings.Contains(err.Error(), "require an export") {
		t.Fatalf("DLL arguments without export: %v", err)
	}

	exe := syntheticPE(false, false, "")
	instance, _, _, err = Build(Config{
		Payload: exe, ModuleType: ModuleNativeExecutable,
		Arguments: `one "two words"`, Entropy: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	mod = instance[instanceModOff:]
	if got := cString(mod[1036:1292]); got != `AAAA one "two words"` {
		t.Fatalf("EXE command line = %q", got)
	}
	if got := u32(mod, 1296); got != 0 {
		t.Fatalf("EXE Unicode flag = %d", got)
	}
	_, _, _, err = Build(Config{Payload: exe, ModuleType: ModuleNativeExecutable, Unicode: true, Entropy: 1})
	if err == nil || !strings.Contains(err.Error(), "native DLL") {
		t.Fatalf("Unicode flag on EXE: %v", err)
	}
}

func TestAPLibModuleHeaderAndPayload(t *testing.T) {
	payload := bytes.Repeat([]byte("ABCDABCDABCD"), 128)
	instance, _, _, err := Build(Config{
		Payload: payload, ModuleType: ModuleJScript,
		Compression: 2, Entropy: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	mod := instance[instanceModOff:]
	if got := u32(mod, 8); got != 2 {
		t.Fatalf("module compression = %d", got)
	}
	if got := u32(mod, 1324); got != uint32(len(payload)) {
		t.Fatalf("module uncompressed length = %d", got)
	}
	zlen := int(u32(mod, 1320))
	if zlen == 0 || zlen >= len(payload) {
		t.Fatalf("compressed payload length = %d", zlen)
	}
	if _, err := referenceDepack(mod[moduleDataOffset:moduleDataOffset+zlen], payload); err != nil {
		t.Fatalf("packed module does not round-trip: %v", err)
	}
}

func TestManagedPEModeAndRuntime(t *testing.T) {
	image := syntheticPE(false, true, "")
	instance, _, _, err := Build(Config{Payload: image, ModuleType: ModuleDotNetExecutable, Entropy: 1})
	if err != nil {
		t.Fatalf("managed PE32 executable: %v", err)
	}
	mod := instance[instanceModOff:]
	if got := cString(mod[12:268]); got != "v2.0.50727" {
		t.Fatalf("runtime = %q, want v2.0.50727", got)
	}
	if cString(mod[1036:1292]) != "AAAA" || u32(mod, 1292) != 1 {
		t.Fatal("managed typed argv boundary not preserved")
	}
	_, _, _, err = Build(Config{Payload: image, ModuleType: ModuleNativeExecutable, Entropy: 1})
	if err == nil || !strings.Contains(err.Error(), "expected") {
		t.Fatalf("managed/native mismatch error = %v", err)
	}
	image[0x98+96] = 0x00 // export RVA 0x1000 (mixed assembly)
	image[0x98+97] = 0x10
	_, _, _, err = Build(Config{Payload: image, ModuleType: ModuleDotNetExecutable, Entropy: 1})
	if err == nil || !strings.Contains(err.Error(), "mixed") {
		t.Fatalf("mixed assembly error = %v", err)
	}
}

func TestManagedArgumentsWireLayout(t *testing.T) {
	for _, test := range []struct {
		name       string
		moduleType int
		dll        bool
	}{
		{"executable", ModuleDotNetExecutable, false},
		{"DLL", ModuleDotNetDLL, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := `one "two words"`
			instance, _, _, err := Build(Config{
				Payload: syntheticPE(test.dll, true, ""), ModuleType: test.moduleType,
				Class: "Example.Entry", Method: "Run", Arguments: args, Entropy: 1,
			})
			if err != nil {
				t.Fatal(err)
			}
			mod := instance[instanceModOff:]
			if got := cString(mod[1036:1292]); got != `AAAA one "two words"` {
				t.Fatalf("managed command line = %q", got)
			}
			if got := u32(mod, 1292); got != 1 {
				t.Fatalf("managed args_skip = %d", got)
			}
		})
	}
	_, _, _, err := Build(Config{Payload: []byte("WScript.Echo 1"), ModuleType: ModuleVBScript, Arguments: "one", Entropy: 1})
	if err == nil || !strings.Contains(err.Error(), "only supported for PE") {
		t.Fatalf("script arguments accepted: %v", err)
	}
}

func syntheticPE(dll, managed bool, export string) []byte {
	image := make([]byte, 0x600)
	copy(image, "MZ")
	binary.LittleEndian.PutUint32(image[0x3c:], 0x80)
	copy(image[0x80:], "PE\x00\x00")
	fh := image[0x84:]
	if managed {
		binary.LittleEndian.PutUint16(fh[0:], 0x14c)
		binary.LittleEndian.PutUint16(fh[16:], 224)
	} else {
		binary.LittleEndian.PutUint16(fh[0:], 0x8664)
		binary.LittleEndian.PutUint16(fh[16:], 240)
	}
	binary.LittleEndian.PutUint16(fh[2:], 1)
	if dll {
		binary.LittleEndian.PutUint16(fh[18:], 0x2000)
	}
	opt := image[0x98:]
	dirStart, secStart := 112, 0x188
	if managed {
		binary.LittleEndian.PutUint16(opt, 0x10b)
		dirStart, secStart = 96, 0x178
	} else {
		binary.LittleEndian.PutUint16(opt, 0x20b)
	}
	binary.LittleEndian.PutUint32(opt[60:], 0x200)
	if managed {
		binary.LittleEndian.PutUint32(opt[92:], 16)
		binary.LittleEndian.PutUint32(opt[dirStart+14*8:], 0x1000)
	} else {
		binary.LittleEndian.PutUint32(opt[108:], 16)
	}
	if export != "" {
		binary.LittleEndian.PutUint32(opt[dirStart:], 0x1000)
	}
	sec := image[secStart:]
	copy(sec, ".rdata")
	binary.LittleEndian.PutUint32(sec[8:], 0x400)
	binary.LittleEndian.PutUint32(sec[12:], 0x1000)
	binary.LittleEndian.PutUint32(sec[16:], 0x400)
	binary.LittleEndian.PutUint32(sec[20:], 0x200)
	if managed {
		binary.LittleEndian.PutUint32(image[0x208:], 0x1050)
		copy(image[0x250:], "BSJB")
		binary.LittleEndian.PutUint32(image[0x25c:], 12)
		copy(image[0x260:], "v2.0.50727\x00")
	} else if export != "" {
		binary.LittleEndian.PutUint32(image[0x200+24:], 1)
		binary.LittleEndian.PutUint32(image[0x200+32:], 0x1050)
		binary.LittleEndian.PutUint32(image[0x250:], 0x1060)
		copy(image[0x260:], export+"\x00")
	}
	return image
}

func u32(data []byte, offset int) uint32 { return binary.LittleEndian.Uint32(data[offset:]) }
func u64(data []byte, offset int) uint64 { return binary.LittleEndian.Uint64(data[offset:]) }
func cString(data []byte) string {
	if i := bytes.IndexByte(data, 0); i >= 0 {
		data = data[:i]
	}
	return string(data)
}
