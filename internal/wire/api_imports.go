package wire

import (
	"fmt"
	"strings"
)

const defaultDLLNames = "ole32;oleaut32;wininet;mscoree;shell32"

// DLLNamesForAPIImports validates the fixed 64-slot native API table and
// returns the DLL preload string required by its imports. The built-in preload
// prefix is preserved for compatibility with the embedded loader.
func DLLNamesForAPIImports(imports []APIImport) (string, error) {
	if len(imports) == 0 || len(imports) > 64 {
		return "", fmt.Errorf("API import list must contain 1..64 entries")
	}
	if imports[0] != (APIImport{Module: "kernel32.dll", Name: "LoadLibraryA"}) {
		return "", fmt.Errorf("API import slot 0 must be kernel32.dll!LoadLibraryA")
	}
	seenImports := make(map[APIImport]struct{}, len(imports))
	preloaded := map[string]struct{}{
		"kernel32.dll": {}, "ntdll.dll": {}, "ole32.dll": {},
		"oleaut32.dll": {}, "wininet.dll": {}, "mscoree.dll": {},
		"shell32.dll": {},
	}
	names := defaultDLLNames
	for i, imp := range imports {
		if !validDLLName(imp.Module) {
			return "", fmt.Errorf("API import %d has an invalid DLL name %q", i, imp.Module)
		}
		if len(imp.Name) == 0 || len(imp.Name) > 127 {
			return "", fmt.Errorf("API import %d has an invalid export name length", i)
		}
		for j := 0; j < len(imp.Name); j++ {
			if imp.Name[j] < 33 || imp.Name[j] > 126 {
				return "", fmt.Errorf("API import %d has a non-ASCII or control export name", i)
			}
		}
		if _, duplicate := seenImports[imp]; duplicate {
			return "", fmt.Errorf("duplicate API import %s!%s", imp.Module, imp.Name)
		}
		seenImports[imp] = struct{}{}
		if _, loaded := preloaded[imp.Module]; !loaded {
			names += ";" + imp.Module
			preloaded[imp.Module] = struct{}{}
		}
	}
	// The native parser advances one byte after the final NUL, so leave a
	// second NUL inside the 256-byte dll_names field.
	if len(names) > 254 {
		return "", fmt.Errorf("API DLL preload list exceeds 254 bytes")
	}
	return names, nil
}

func validDLLName(name string) bool {
	if len(name) < len("a.dll") || len(name) > 63 || !strings.HasSuffix(name, ".dll") || name[0] == '.' {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		// The native export resolver lowercases with byte | 0x20, which
		// changes '_' into DEL rather than preserving it.
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' {
			continue
		}
		return false
	}
	return true
}
