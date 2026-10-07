package assets

import _ "embed"

// These checked-in x64 Windows loader images come from Fritter's generated
// loader headers. They are native runtime code; Churro generation uses Go only.
//
//go:embed loader_peb1_exe_x64.bin
var LoaderPEB1 []byte

//go:embed loader_peb2_exe_x64.bin
var LoaderPEB2 []byte

//go:embed dispatch_shim_exe_x64.bin
var DispatchShim []byte

//go:embed loader_peb1_metadata.json
var LoaderPEB1Metadata []byte

//go:embed loader_peb2_metadata.json
var LoaderPEB2Metadata []byte
