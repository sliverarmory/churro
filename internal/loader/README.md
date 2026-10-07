# Native loader build source

This directory contains the build-time C source, PE extractor, and Go build
tools for Churro's embedded x64 Windows loader images. It comes from Fritter
commit `ff952a22b1cf06d41b3781ab7c20f608b9754e53`. The Churro host
generator remains Go; these sources are used only when regenerating the
native loader bundle.

Churro carries these source changes:

- `loader/inmem_pe.c` reads the TLS directory RVA from saved `ntc`, after the
  original mapped header may have been unmapped or overwritten.
- `include/poly_section.h` uses named MinGW code sections for tagged loader
  functions. `exe2h` packs the six loader sections and emits function and
  cross-section reference tables. `table2json` converts those tables to the
  metadata Churro needs for per-function dispatch.
- Local declarations replace the unused upstream `aplib.h`, `depack.h`, and
  Microsoft packing headers. The copied `loader/depack.c` is the runtime
  aPLib-compatible decoder. `internal/wire/aplib.go` is an independently
  written Go encoder for the same token stream; it does not copy a third-party
  packer implementation. The copied Fritter source and our changes are
  distributed under the repository's BSD 3-Clause license.

In multi-section output, `.text` and `.hash_ch` stay resident. The hash
resolver can run on both the loader thread and a newly created module thread;
encrypting it during another call would race. The other four sections use
call thunks. The shim's protection and wipe length includes the appended
dispatcher and thunk tail.

Host continuation resolves `RtlCaptureContext` through the existing PEB/hash
resolver to capture the running thread before `NtContinue`. This keeps the
61-import wire layout unchanged; `GetThreadContext` cannot provide a valid
context for the current running thread.

`scripts/rebuild-loader-blobs.sh` builds both PEB variants and the dispatch
shim with x64 MinGW, then emits `*.bin`, `*_metadata.json`, and `bundle.json`
into `internal/assets/`. It checks the pinned Poly/API headers before a normal
rebuild. The manifest includes image hashes and the Poly/API metadata compiled
into those images. `buildmeta` also generates the matching Go defaults in
`internal/wire/generated_constants.go` for an embedded rebuild.

For a custom multi-section bundle, references into protected sections must
be direct x64 `CALL rel32` instructions (`E8` with a five-byte instruction
and displacement at byte 1). The Go generator validates this before patching
thunks; RIP-relative data accesses, jumps, and conditional branches cannot
use call dispatch. The current dispatcher forwards the four Win64 register
arguments (`RCX`, `RDX`, `R8`, `R9`) and the return value. Protected callees
in custom bundles must not require stack arguments.

To create a reproducible custom build without changing embedded assets:

```sh
./scripts/rebuild-loader-blobs.sh --rotate --seed 0x12345678 --output-dir /tmp/churro-loader-bundle
```

Use `-loader-bundle /tmp/churro-loader-bundle` with the CLI. `--rotate`
without `--seed` chooses a fresh seed; the generated `poly_seed.h` and
`api_shuffle.h` are included in the output directory. Repeating a seed with
the same compiler and source tree reproduces the Poly/API choices. The two
PEB images remain separate to preserve the loader's PEB walk variation.

The build script uses the host C compiler for `exe2h` and x64 MinGW for the
Windows images. Zig 0.17.0 was tried on macOS but rejected
`-fno-toplevel-reorder`; without that flag its Windows GNU target lacked
target C headers. MinGW is the validated image compiler for this source.
