# Embedded Windows loader images

The `.bin` files are exact byte extractions of the x64 Windows loader images
committed in `sliverarmory/Fritter` under `generated/` at the source commit
recorded in Churro's README. The `poly_seed.h` and `api_shuffle.h` metadata
must stay paired with these images: the loader uses the corresponding cipher,
hash rotations and API table order. Updates must regenerate the set together.

The host-side generator is Go and needs no C compiler or CGO at runtime. These
images are native x64 Windows code produced from Fritter's C loader.
