# Embedded Windows loader assets

The checked-in x64 images are built from the Fritter source at commit
`ff952a22b1cf06d41b3781ab7c20f608b9754e53`, using the copied source in
`internal/loader/`. Churro's host generator is Go; it reads these native
runtime images and their metadata without invoking a C compiler.

The copied source has three deliberate changes: `loader/inmem_pe.c` reads the
TLS directory RVA from the saved `ntc` header; `include/poly_section.h`
places named loader functions in distinct MinGW code sections; and unused
external header declarations were replaced with local declarations. The
new images therefore differ from the original Fritter build. The loader PE
extractor emits six code sections and 60 cross-section references for each
PEB variant. Churro uses the JSON metadata to patch those references and
manage the protected sections at generation time.

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
| `loader_peb1_exe_x64.bin` | `f5b33084afe205b1d2fd03bb9a0b0a650f8c6d8292198471d68f3b72eaa50bc6` |
| `loader_peb2_exe_x64.bin` | `3d6083556fc4c532999c416de936e617d6f507253bcedddd9514e179de5ec392` |
| `dispatch_shim_exe_x64.bin` | `bf541d84ae3e486b14491b21c56af0754cde25bd18041964608a1e6688c6f33d` |
| `loader_peb1_metadata.json` | `f0e85e077f17b6718b9fe7f19e780888206f3dc5f46942fa34aa6b1356a95476` |
| `loader_peb2_metadata.json` | `f0e85e077f17b6718b9fe7f19e780888206f3dc5f46942fa34aa6b1356a95476` |
| `bundle.json` | `becca7d4c949c70dac1013856f64b9ee50f8f71f2d86e6670ebc768c806f3b17` |
| `poly_seed.h` | `eebc79264f6727543a7e008551482cc2dadf48cfbdce6cba0433257c0734fb74` |
| `api_shuffle.h` | `e1c0876d49cae62f9ad8bc86b1493655f7caffad4eb238011772bfa55eb75a0a` |
| `api_master.h` | `cd0a8d082141f065b521ad4f3c4217b0f8a30f86ac4c600c5a784b7c21461677` |
