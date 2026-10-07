# Embedded Windows loader assets

The checked-in x64 images are built from the Fritter source at commit
`ff952a22b1cf06d41b3781ab7c20f608b9754e53`, using the copied source in
`internal/loader/`. Churro's host generator is Go; it reads these native
runtime images and their metadata without invoking a C compiler.

The copied source has four deliberate changes: `loader/inmem_pe.c` reads the
TLS directory RVA from the saved `ntc` header and converts UTF-8 native DLL
arguments to the target ANSI code page; `include/poly_section.h` places named
loader functions in distinct MinGW code sections; and unused external header
declarations were replaced with local declarations. The new images therefore
differ from the original Fritter build. The loader PE extractor emits six code
sections and 62 cross-section references for each PEB variant. Churro uses the
JSON metadata to patch those references and manage the protected sections at
generation time. `.text` stays resident. The other five sections, including
`.hash_ch`, are dispatched on demand. The dispatcher counts active calls per
section and encrypts a section after its final caller returns, so concurrent
hash-resolver calls can share decrypted code safely.

`bundle.json` records schema version 1, the Poly cipher/hash constants, the
API import order, both function/reference tables, and SHA-256 hashes for
the three images. The generated `internal/wire/generated_constants.go` is
derived from the same pinned `poly_seed.h` and `api_shuffle.h` headers. The
current Poly build seed is `0xDA44B96C`; the first API slot is
`kernel32.dll!LoadLibraryA`, and there are 61 imports.

Run `./scripts/rebuild-loader-blobs.sh` with Go, a host C compiler, and x64
MinGW to reproduce the pinned assets. The script checks the copied headers
against the pinned asset headers before building. To make a custom bundle
without changing embedded defaults, run:

```sh
./scripts/rebuild-loader-blobs.sh --rotate --seed 0x12345678 --output-dir /tmp/churro-loader-bundle
```

The CLI accepts that directory with `-loader-bundle`. Omitting `--seed`
selects a fresh build seed. Rebuilding into `internal/assets` also updates
the generated Go constants; a rotated embedded build replaces the copied
Poly/API headers so future pinned rebuilds use its values.

| Asset | SHA-256 |
| --- | --- |
| `loader_peb1_exe_x64.bin` | `2ea072d6b079d9ab085cb3c543fe694704b44f6747f84479e3cadf87c0d2e56b` |
| `loader_peb2_exe_x64.bin` | `b353548705a467d7bfe7212e793785f9e29738705a812d4376b7e6326b77efc6` |
| `dispatch_shim_exe_x64.bin` | `bf541d84ae3e486b14491b21c56af0754cde25bd18041964608a1e6688c6f33d` |
| `loader_peb1_metadata.json` | `b0b14974a62d91a7ac3fc7ff43114445177a089bd5da0b4fbab120f27c731e92` |
| `loader_peb2_metadata.json` | `b0b14974a62d91a7ac3fc7ff43114445177a089bd5da0b4fbab120f27c731e92` |
| `bundle.json` | `c77049f088f9dec926362b837fde72b86a1dbc0734de448e0d77d11421abbbee` |
| `poly_seed.h` | `eebc79264f6727543a7e008551482cc2dadf48cfbdce6cba0433257c0734fb74` |
| `api_shuffle.h` | `e1c0876d49cae62f9ad8bc86b1493655f7caffad4eb238011772bfa55eb75a0a` |
| `api_master.h` | `cd0a8d082141f065b521ad4f3c4217b0f8a30f86ac4c600c5a784b7c21461677` |
