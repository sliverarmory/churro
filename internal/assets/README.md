# Embedded Windows loader assets

The checked-in x64 images are built from the Fritter source at commit
`ff952a22b1cf06d41b3781ab7c20f608b9754e53`, using the copied source in
`internal/loader/`. Churro's host generator is Go; it reads these native
runtime images and their metadata without invoking a C compiler.

The copied source fixes TLS directory lookup and UTF-8 native DLL arguments,
places tagged loader functions in named PE code sections, and builds resolver
strings on the stack for Zig's C compiler. The new images therefore differ
from the original Fritter build. The loader PE extractor emits six code
sections and 39 cross-section references for each PEB variant. Churro uses the
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

Run `./scripts/rebuild-loader-blobs.sh` with Go and Zig 0.17.0 to reproduce the
pinned assets. The script checks the copied headers against the pinned asset
headers before building. To make a custom bundle without changing embedded
defaults, run:

```sh
./scripts/rebuild-loader-blobs.sh --rotate --seed 0x12345678 --output-dir /tmp/churro-loader-bundle
```

The CLI accepts that directory with `-loader-bundle`. Omitting `--seed`
selects a fresh build seed. Rebuilding into `internal/assets` also updates
the generated Go constants; a rotated embedded build replaces the copied
Poly/API headers so future pinned rebuilds use its values.

| Asset | SHA-256 |
| --- | --- |
| `loader_peb1_exe_x64.bin` | `87e43392a3b92d2ff1c369d34d02c010df78366fbbfbbfb860c537d1a7664d6c` |
| `loader_peb2_exe_x64.bin` | `c58dfb26fdadd839347aad9f4554f9f3b2a377c41073c37d4eae5cf1f407cd8e` |
| `dispatch_shim_exe_x64.bin` | `83038bc4ea0c3e375d663417cedd510110aaedde87a5b1e8cfc90cd71eeff37f` |
| `loader_peb1_metadata.json` | `9ee9817248ca01ed8a6b25077d768e4c3d1d0b7496d6912abe2d9ef97ee68d3a` |
| `loader_peb2_metadata.json` | `9ee9817248ca01ed8a6b25077d768e4c3d1d0b7496d6912abe2d9ef97ee68d3a` |
| `bundle.json` | `49cf0de0e598d65311213a7426be668e022bf0eaed381cdc9a11dcefafe9e768` |
| `poly_seed.h` | `eebc79264f6727543a7e008551482cc2dadf48cfbdce6cba0433257c0734fb74` |
| `api_shuffle.h` | `e1c0876d49cae62f9ad8bc86b1493655f7caffad4eb238011772bfa55eb75a0a` |
| `api_master.h` | `cd0a8d082141f065b521ad4f3c4217b0f8a30f86ac4c600c5a784b7c21461677` |
