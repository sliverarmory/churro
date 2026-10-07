# Native loader source

This is the build-time source for Churro's embedded x64 Windows loader images.
It is based on the required Fritter C source at commit
`ff952a22b1cf06d41b3781ab7c20f608b9754e53`, with one runtime TLS fix in
`loader/inmem_pe.c`. The loader, shim, PE extractor, and required headers are
kept here so `scripts/rebuild-loader-blobs.sh` does not depend on the sibling
Fritter checkout. The pinned Poly and API headers match `internal/assets/`.

The build script uses MinGW for the Windows images and the host C compiler
for `exe2h`. Zig 0.17.0 was tried on macOS but rejected
`-fno-toplevel-reorder`; without that flag, its Windows GNU target lacked
target C headers. MinGW 16.2.0 reproduced the original image byte for byte
before the TLS fix.

The copied source omits the upstream `aplib.h` and `depack.h` files, whose
declarations are unnecessary here except for the one locally declared
`aP_depack` prototype. It also omits the upstream `pshpack*.h` and
`poppack.h` files; `include/pe.h` now scopes the DOS header's required pack
alignment with local `#pragma pack(push, ...)` and `#pragma pack(pop)`.
Removing these headers does not change any of the three generated image hashes.
