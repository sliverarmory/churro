#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_dir="${root}/internal/loader"
custom_source=false
assets_dir="${root}/internal/assets"
zig="${ZIG:-zig}"
output_dir="${assets_dir}"
seed="${CHURRO_BUILD_SEED:-}"
rotate=false

while (($#)); do
  case "$1" in
    --rotate)
      rotate=true
      shift
      ;;
    --seed)
      if (($# < 2)); then echo "--seed requires a value" >&2; exit 2; fi
      seed="$2"
      shift 2
      ;;
    --output-dir)
      if (($# < 2)); then echo "--output-dir requires a path" >&2; exit 2; fi
      output_dir="$2"
      shift 2
      ;;
    --source-dir)
      if (($# < 2)); then echo "--source-dir requires a path" >&2; exit 2; fi
      source_dir="$2"
      custom_source=true
      shift 2
      ;;
    *)
      echo "unknown option: $1" >&2
      exit 2
      ;;
  esac
done
if [[ -n "${seed}" && "${rotate}" != true ]]; then
  echo "--seed requires --rotate" >&2
  exit 2
fi
if [[ "${custom_source}" == true && "${rotate}" != true ]]; then
  echo "--source-dir requires --rotate so api_shuffle.h matches api_master.h" >&2
  exit 2
fi

if [[ ! -d "${source_dir}/include" || ! -d "${source_dir}/loader" ]]; then
  echo "source directory must contain include/ and loader/" >&2
  exit 2
fi
source_dir="$(cd "${source_dir}" && pwd -P)"
mkdir -p "${output_dir}"
output_dir="$(cd "${output_dir}" && pwd -P)"
if [[ "${custom_source}" == true && "${output_dir}" == "${assets_dir}" ]]; then
  echo "--source-dir requires an output directory other than embedded assets" >&2
  exit 2
fi

if ! command -v "${zig}" >/dev/null 2>&1; then
  echo "Zig 0.17.0 is required to rebuild the native loader" >&2
  exit 1
fi
zig_version="$("${zig}" version)"
if [[ "${zig_version}" != "0.17.0" ]]; then
  echo "Zig 0.17.0 is required to rebuild the native loader (found ${zig_version})" >&2
  exit 1
fi
# The Windows image is linked without a C runtime. Point Zig's C frontend
# at the Windows headers shipped inside the pinned Zig distribution.
zig_lib_dir="$("${zig}" env | sed -n 's/^[[:space:]]*\.lib_dir = "\(.*\)",[[:space:]]*$/\1/p')"
zig_windows_headers="${zig_lib_dir}/libc/include/any-windows-any"
if [[ -z "${zig_lib_dir}" || ! -f "${zig_windows_headers}/windows.h" ]]; then
  echo "could not find Windows headers in Zig 0.17.0's bundled library" >&2
  exit 1
fi

if [[ "${rotate}" != true && "${custom_source}" != true ]]; then
  for header in poly_seed.h api_shuffle.h api_master.h; do
    if ! cmp -s "${source_dir}/include/${header}" "${assets_dir}/${header}"; then
      echo "pinned ${header} differs between loader source and embedded assets" >&2
      exit 1
    fi
  done
fi

build_dir="$(mktemp -d "${TMPDIR:-/tmp}/churro-loader.XXXXXXXX")"
trap 'rm -rf "${build_dir}"' EXIT
export ZIG_GLOBAL_CACHE_DIR="${ZIG_GLOBAL_CACHE_DIR:-${build_dir}/zig-cache}"
work_source="${build_dir}/source"
staged="${build_dir}/bundle"
cp -R "${source_dir}" "${work_source}"
mkdir -p "${staged}"

go_cache="${GOCACHE:-${build_dir}/gocache}"
go_module_cache="${GOMODCACHE:-${build_dir}/gomodcache}"
(cd "${root}" && GOCACHE="${go_cache}" GOMODCACHE="${go_module_cache}" \
  go build -o "${build_dir}/header2bin" ./internal/loader/header2bin)
(cd "${root}" && GOCACHE="${go_cache}" GOMODCACHE="${go_module_cache}" \
  go build -o "${build_dir}/table2json" ./internal/loader/table2json)
(cd "${root}" && GOCACHE="${go_cache}" GOMODCACHE="${go_module_cache}" \
  go build -o "${build_dir}/buildmeta" ./internal/loader/buildmeta)

if [[ "${rotate}" == true ]]; then
  "${build_dir}/buildmeta" rotate "${work_source}/include" "${seed}"
fi

"${zig}" cc -O2 -I "${work_source}/include" \
  "${work_source}/exe2h/exe2h.c" -o "${build_dir}/exe2h"

loader_flags=(
  -target x86_64-windows-gnu
  -DWIN32_LEAN_AND_MEAN
  -fno-builtin
  -fpack-struct=8
  -fPIC
  -O1
  -nostdlib
  -fno-jump-tables
  -fno-optimize-sibling-calls
  -fno-vectorize
  -fno-slp-vectorize
  -isystem "${zig_windows_headers}"
)
loader_sources=(
  "${work_source}/loader/loader.c"
  "${work_source}/loader/depack.c"
  "${work_source}/loader/clib.c"
  "${work_source}/hash.c"
  "${work_source}/encrypt.c"
)

for order in 1 2; do
  name="loader_peb${order}"
  "${zig}" cc -D"PEB_WALK_ORDER=${order}" \
    "${loader_flags[@]}" "${loader_sources[@]}" \
    -I "${work_source}/include" -Wl,--entry,FritterLoader \
    -o "${build_dir}/${name}.exe"
  (cd "${build_dir}" && ./exe2h "${name}.exe")
  "${build_dir}/header2bin" \
    "${build_dir}/${name}_exe_x64.h" "${staged}/${name}_exe_x64.bin"
  "${build_dir}/table2json" \
    "${build_dir}/${name}_fn_table_x64.h" \
    "${build_dir}/${name}_ref_table_x64.h" \
    "${staged}/${name}_metadata.json"
done

"${zig}" cc "${loader_flags[@]}" \
  "${work_source}/loader/dispatch_shim.c" \
  -I "${work_source}/include" -Wl,--entry,DispatchShimEntry \
  -o "${build_dir}/dispatch_shim.exe"
(cd "${build_dir}" && ./exe2h dispatch_shim.exe)
"${build_dir}/header2bin" \
  "${build_dir}/dispatch_shim_exe_x64.h" "${staged}/dispatch_shim_exe_x64.bin"

go_constants="-"
if [[ "${output_dir}" == "${assets_dir}" ]]; then
  go_constants="${build_dir}/generated_constants.go"
fi
"${build_dir}/buildmeta" manifest "${work_source}/include" "${staged}" "${go_constants}"
if [[ "${go_constants}" != "-" ]]; then
  gofmt -w "${go_constants}"
fi
for header in poly_seed.h api_shuffle.h api_master.h; do
  cp "${work_source}/include/${header}" "${staged}/${header}"
done

# Read the finished bundle through the public Go CLI and exercise the
# call-dispatch preparation before any embedded asset is replaced.
(cd "${root}" && GOCACHE="${go_cache}" GOMODCACHE="${go_module_cache}" \
  go build -o "${build_dir}/churro-gen" ./cmd/churro-gen)
"${build_dir}/churro-gen" \
  -input "${root}/testdata/windows-e2e/hello.js" \
  -loader-bundle "${staged}" \
  -output "${build_dir}/loader-smoke.bin" >/dev/null
if [[ ! -s "${build_dir}/loader-smoke.bin" ]]; then
  echo "Zig loader bundle did not generate shellcode" >&2
  exit 1
fi

mkdir -p "${output_dir}"
for file in \
  loader_peb1_exe_x64.bin loader_peb2_exe_x64.bin dispatch_shim_exe_x64.bin \
  loader_peb1_metadata.json loader_peb2_metadata.json bundle.json \
  poly_seed.h api_shuffle.h api_master.h; do
  cp "${staged}/${file}" "${output_dir}/${file}"
  echo "updated ${output_dir}/${file}"
done
if [[ "${output_dir}" == "${assets_dir}" ]]; then
  cp "${go_constants}" "${root}/internal/wire/generated_constants.go"
  if [[ "${rotate}" == true ]]; then
    cp "${staged}/poly_seed.h" "${source_dir}/include/poly_seed.h"
    cp "${staged}/api_shuffle.h" "${source_dir}/include/api_shuffle.h"
  fi
  echo "updated ${root}/internal/wire/generated_constants.go"
fi
