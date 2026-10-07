#!/usr/bin/env bash
set -euo pipefail

if (($# != 1)); then
  echo "usage: $0 OUTPUT_DIR" >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/churro-custom-api.XXXXXXXX")"
trap 'rm -rf "${work}"' EXIT
source_dir="${work}/loader"
cp -R "${root}/internal/loader" "${source_dir}"

# Add a real export from a DLL absent from the embedded preload list. The
# extra typed field is compiled into both PEB variants but is not called by
# the loader, so resolving it is the behavior this fixture exercises.
cat >> "${source_dir}/include/api_master.h" <<'EOF'
XAPI(ADVAPI32_DLL, "GetUserNameA", GetUserNameA_t, GetUserNameA)
EOF
winapi="${source_dir}/loader/winapi.h"
sed '$d' "${winapi}" > "${winapi}.new"
cat >> "${winapi}.new" <<'EOF'
    typedef BOOL (WINAPI *GetUserNameA_t)(LPSTR lpBuffer, LPDWORD pcbBuffer);
#endif
EOF
mv "${winapi}.new" "${winapi}"

"${root}/scripts/rebuild-loader-blobs.sh" \
  --source-dir "${source_dir}" \
  --rotate --seed 0x12345678 --output-dir "$1"
