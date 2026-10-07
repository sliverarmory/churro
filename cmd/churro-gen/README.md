# churro-gen native loader bundles

`churro-gen` accepts native `.exe` and `.dll`, managed `.exe` and `.dll`,
`.vbs`, and `.js` inputs. `-args` supplies a raw command-line tail to native
and managed executables. The managed entry point receives parsed `string[]`
arguments. With a managed DLL, `-class` and `-method` select a public static
method, and `-args` is parsed into one string per method parameter. Quote
arguments containing spaces according to Windows command-line rules. With a
native DLL, `-method` selects an export and `-args` supplies its single string
argument; `-unicode` passes that argument as UTF-16. `-args` is limited to
250 bytes and is unavailable for scripts. `-fork` takes a hexadecimal host
entry-point RVA for host continuation.

Output formats are `bin`, `base64`, `c`, `ruby`, `python`, `powershell`,
`csharp`, `hex`, and `uuid`, with Fritter-compatible numeric values 1 through
9. Without `-output`, the CLI chooses `loader.bin`, `loader.b64`, `loader.c`,
`loader.rb`, `loader.py`, `loader.ps1`, `loader.cs`, `loader.hex`, or
`loader.uuid` according to the format. The CLI uses the Go aPLib packer by
default, matching Fritter's native CLI; `-compression none` leaves module bytes
uncompressed. The Go API retains its zero-value `CompressionNone` default.

For HTTP staging, set `-server` to an HTTP or HTTPS base URL and optionally
set `-modname` to an eight-byte-or-shorter module filename. The CLI writes the
loader to `-output` and the separate module beside it, or to `-module-output`
when specified. Host the module at the URL reported by the generator.

The CLI accepts native Fritter's short flag aliases: `-i` input, `-o`
output, `-c` class, `-m` method, `-r` runtime, `-d` domain, `-f` format,
`-x` exit, `-e` entropy, `-k` headers, `-j` decoy, `-t` thread, `-p`
args, `-w` unicode, `-y` fork, `-s` server, and `-n` module name. Format
aliases include `rb`, `py`, `ps`, and `cs`; exit accepts `1` to `3`, entropy
accepts `1` to `3` and `none`/`low`/`full`, and headers accepts `1` or `2`.
The CLI's default entropy is `default` (names and crypto).
Legacy long aliases `-file`, `-function`, `-params`, and `-oep` are accepted.
The deprecated `-chunked` (`-g`) flag accepts `0` or `1` for command-line
compatibility; the dispatch shim is always used.

## Custom bundle

The default `churro-gen` build uses the loader images embedded in the Go
package. Use `-loader-bundle DIR` to generate with a different native loader
build. The directory must contain four regular files:

- `loader_peb1_exe_x64.bin`
- `loader_peb2_exe_x64.bin`
- `dispatch_shim_exe_x64.bin`
- `bundle.json`

`bundle.json` has this schema. This illustration abbreviates the API and
function tables and uses hash placeholders, so it is not a usable manifest:

```json
{
  "schema": 1,
  "poly": {
    "cipher_rotations": [4, 4, 16, 23, 22, 11],
    "cipher_rounds": 20,
    "hash_rot_a": 3,
    "hash_rot_b": 13,
    "hash_rounds": 27
  },
  "api_imports": [
    {"module": "kernel32.dll", "name": "LoadLibraryA"}
  ],
  "peb1_metadata": {
    "functions": [{"offset": 0, "size": 11200, "single_page": false, "name": ".text"}],
    "references": []
  },
  "peb2_metadata": {
    "functions": [{"offset": 0, "size": 11200, "single_page": false, "name": ".text"}],
    "references": []
  },
  "sha256": {
    "peb1": "64 lowercase hex digits",
    "peb2": "64 lowercase hex digits",
    "dispatch_shim": "64 lowercase hex digits"
  }
}
```

The real API list must contain the 61 module/export pairs required by the
copied native runtime, plus up to three additional unique imports. The pairs
may be reordered in the native build, but `kernel32.dll!LoadLibraryA` must
remain in slot 0. Every module name is a lowercase ASCII `.dll` basename;
export names are printable ASCII. The Go generator appends additional DLLs to
the native preload list, which must fit its 256-byte field. The Poly constants
and API order must come from the same native build. The SHA-256 fields bind
the manifest to the three image files; they cannot prove that an opaque native
image was compiled with the claimed constants. Generate the manifest alongside
the images with `scripts/rebuild-loader-blobs.sh`, and keep those four files
together. The generated `internal/assets/bundle.json` is a complete example.

To extend the native import table, copy `internal/loader`, add an `XAPI` line
to its `include/api_master.h` and any required function-pointer typedef to
`loader/winapi.h`, then build with `--source-dir`, `--rotate`, and a separate
`--output-dir`. The test helper below creates a 62-import bundle that resolves
`advapi32.dll!GetUserNameA`:

```sh
./scripts/build-custom-api-test-bundle.sh /tmp/churro-extra-api
churro-gen -input payload.dll -method Start -loader-bundle /tmp/churro-extra-api
```

Multi-section images list every extracted function and cross-section
reference in their respective metadata tables. Each reference has
`src_blob_off`, `inst_length`, `disp_offset`, `src_fn`, and `target_fn` fields.
The image, table, and API/Poly metadata must be produced by the same build.

```sh
churro-gen -input payload.dll -method StartW \
  -loader-bundle ./my-loader -output payload.bin
```

The CLI rejects unknown manifest fields, symlinked files, missing or repeated
dispatch metadata, changed image hashes, and invalid Poly or API tables.
