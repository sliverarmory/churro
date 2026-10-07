# Pinned Windows loader images

These binary images were built from the Fritter source at commit
`ff952a22b1cf06d41b3781ab7c20f608b9754e53`. The build sources and
metadata are copied into `internal/loader/`; generation by the Churro Go
package uses only the checked-in images.

The only runtime behavior change from that commit is in
`internal/loader/loader/inmem_pe.c`: the TLS directory RVA is read from the
saved `ntc` header. The original read used `ntnew` after the first mapped
view was unmapped, and after mapped headers could have been overwritten.
The copied source also replaces unused third-party compression headers with
the single needed `aP_depack` declaration and scopes PE DOS-header packing
directly in its extractor header. These declaration changes leave the images
byte-identical.

Run `./scripts/rebuild-loader-blobs.sh` with Go, a host C compiler, and an
x64 MinGW compiler to regenerate the images. The script compares the copied
`poly_seed.h`, `api_shuffle.h`, and `api_master.h` with these pinned asset
headers before compiling, and requires the loader images to have one code
section and zero cross-section references.

| Asset | SHA-256 |
| --- | --- |
| `loader_peb1_exe_x64.bin` | `66c1d136c5e92c1114ecab57efa98c9aad88616ffe471001052799165d1e654d` |
| `loader_peb2_exe_x64.bin` | `da8ea7377185295151d84f548a2cdd298c897b41678d0e1c7eb67e99e30a331d` |
| `dispatch_shim_exe_x64.bin` | `bf541d84ae3e486b14491b21c56af0754cde25bd18041964608a1e6688c6f33d` |
| `poly_seed.h` | `eebc79264f6727543a7e008551482cc2dadf48cfbdce6cba0433257c0734fb74` |
| `api_shuffle.h` | `e1c0876d49cae62f9ad8bc86b1493655f7caffad4eb238011772bfa55eb75a0a` |
| `api_master.h` | `cd0a8d082141f065b521ad4f3c4217b0f8a30f86ac4c600c5a784b7c21461677` |

For comparison, rebuilding the unmodified Fritter source with the same pinned
headers reproduces the prior PEB1 image byte for byte (SHA-256
`5e160c2a0ad0d8caaf221a2430b94dcb1c6672941e8e12eb85c956a49cb7d35d`).
The prior PEB2 image had SHA-256
`551190f23d24ec94c7a52128fa213d4ce676cc4b2ab6893ad62ee454374955a8`.
The dispatch shim image did not change.
