#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_dir="${root}/internal/loader"
assets_dir="${root}/internal/assets"
host_cc="${HOST_CC:-cc}"
mingw_cc="${MINGW_CC:-x86_64-w64-mingw32-gcc}"

for header in poly_seed.h api_shuffle.h api_master.h; do
  if ! cmp -s "${source_dir}/include/${header}" "${assets_dir}/${header}"; then
    echo "pinned ${header} differs between loader source and embedded assets" >&2
    exit 1
  fi
done

build_dir="$(mktemp -d "${TMPDIR:-/tmp}/churro-loader.XXXXXXXX")"
trap 'rm -rf "${build_dir}"' EXIT

"${host_cc}" -I "${source_dir}/include" \
  "${source_dir}/exe2h/exe2h.c" -o "${build_dir}/exe2h"
(cd "${root}" && GOMODCACHE="${GOMODCACHE:-${build_dir}/gomodcache}" \
  go build -o "${build_dir}/header2bin" ./internal/loader/header2bin)

loader_flags=(
  -fno-toplevel-reorder
  -fno-builtin
  -fpack-struct=8
  -fPIC
  -O1
  -nostdlib
)
loader_sources=(
  "${source_dir}/loader/loader.c"
  "${source_dir}/loader/depack.c"
  "${source_dir}/loader/clib.c"
  "${source_dir}/hash.c"
  "${source_dir}/encrypt.c"
)

for order in 1 2; do
  name="loader_peb${order}"
  "${mingw_cc}" -D"PEB_WALK_ORDER=${order}" \
    "${loader_flags[@]}" "${loader_sources[@]}" \
    -I "${source_dir}/include" -o "${build_dir}/${name}.exe"
  (cd "${build_dir}" && ./exe2h "${name}.exe")
  if ! grep -qx "#define LOADER_PEB${order}_FN_COUNT 1" \
      "${build_dir}/${name}_fn_table_x64.h"; then
    echo "${name} is not a one-section loader" >&2
    exit 1
  fi
  if ! grep -qx "#define LOADER_PEB${order}_REF_COUNT 0" \
      "${build_dir}/${name}_ref_table_x64.h"; then
    echo "${name} has cross-section references" >&2
    exit 1
  fi
  "${build_dir}/header2bin" \
    "${build_dir}/${name}_exe_x64.h" "${build_dir}/${name}_exe_x64.bin"
done

"${mingw_cc}" "${loader_flags[@]}" \
  "${source_dir}/loader/dispatch_shim.c" \
  -I "${source_dir}/include" -o "${build_dir}/dispatch_shim.exe"
(cd "${build_dir}" && ./exe2h dispatch_shim.exe)
"${build_dir}/header2bin" \
  "${build_dir}/dispatch_shim_exe_x64.h" "${build_dir}/dispatch_shim_exe_x64.bin"

for name in loader_peb1_exe_x64 loader_peb2_exe_x64 dispatch_shim_exe_x64; do
  cp "${build_dir}/${name}.bin" "${assets_dir}/${name}.bin"
  echo "updated ${assets_dir}/${name}.bin"
done
