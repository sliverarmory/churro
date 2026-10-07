# Fritter feature parity roadmap

Churro keeps a Go-only host generator and does not use WebAssembly. The Windows
runtime may use checked-in native loader images built from source in this
repository. This roadmap compares Churro with Fritter at
`ff952a22b1cf06d41b3781ab7c20f608b9754e53` and tracks implementation
and execution evidence separately.

## Acceptance rule

Check an implementation item only after code and focused tests are committed.
Check an execution item only after its named Windows Actions job passes at the
implementation code commit. A later documentation-only evidence update does
not invalidate that run. Keep unsupported or unverified behavior visible here.
Publication requires a tagged release and independently verified hashes.

## Baseline

- [x] Six typed payload families and nine output formats in the Go API.
- [x] Windows execution of Go, import-using native, and lifecycle native DLLs
  under both PE-header modes.
- [x] Generated Sliver shared library opens a matching mTLS session and appears
  in `GetSessions`.

Baseline proof: [Windows Actions run 37554694955](https://github.com/sliverarmory/churro/actions/runs/37554694955)
at `0cff53bd0733d353c642ba8cff346894a74a8552`.

Implementation checkpoint: [PR #1](https://github.com/sliverarmory/churro/pull/1)
on `feat/fritter-parity` at `cc555c781340499a904a885a6725f0fcefe06a7b`.
Local `go test ./...`, `go test -race ./...`, `go vet ./...`, Windows test
cross-compilation and vet, all 11 CLI cross-builds, and a byte-for-byte pinned
loader rebuild passed. Windows execution evidence is recorded below.

## 1. Public API and CLI parity

- [x] Add native invocation arguments and Unicode selection, with validation
  and wire-format tests.
- [x] Add managed EXE and DLL invocation arguments to the public Go API and CLI,
  preserving parameterless calls and quoted argument parsing.
- [x] Expose host-image continuation RVA in `churro-gen` and test the mapping to
  the Go request.
- [x] Restore stable typed generation errors with documented codes and tests
  for invalid PE, export, architecture, and staging inputs.
- [x] Support a validated custom native loader bundle with matching cipher and
  API metadata through both the Go API and CLI, without a WASM module.
- [x] Accept added API imports in a custom native bundle up to the loader's
  64-slot table limit; a 62-import bundle builds locally through MinGW.
- [x] Cover legacy native CLI format/entropy/exit aliases, output naming, and
  staged-module placement where compatibility is useful; document any
  deliberate default differences.

- [x] Copy Base64 CLI output to the Windows clipboard as CF_TEXT on a best-effort
  basis, matching Fritter's convenience side effect; the Windows readback test
  passed.
- [x] Default staged-module output to the process working directory, matching
  Fritter even when the loader output is in another directory. Write the module
  before the loader and print a concise native-compatible success report;
  focused CLI tests and Windows package tests passed.
- [x] Reject loader or staged-module output paths that alias the input or each
  other, including symlinks, hard links, and Windows case variants; focused
  CLI tests and Windows package tests passed.
- [x] Honor context cancellation during compression, encryption, loader
  assembly, and output formatting, and let `Close` finish promptly after a
  canceled generation; deterministic unit and race tests passed.
- [x] Include payload type, native or managed invocation, and the complete
  credential-free staged URL in the CLI success report; focused Go tests pass.
- [x] Accept Fritter native CLI help and attached-value spellings, including
  `-?` and `-o:path`, and continue parsing options after stray positionals.
- [x] Select EXE versus DLL behavior from PE headers for files with `.exe` or
  `.dll` names, including renamed native and managed images.

Churro wraps invalid generation inputs in `GenerationError` so callers can use
stable codes. The underlying `ValidationError` remains available through
`errors.As`; Fritter returns it directly at the top level.
Churro's CLI defaults to `EntropyDefault` and aPLib, following Fritter's
native C CLI. Fritter's older Go/WASM CLI defaults to `EntropyNone` and no
compression; `-entropy none -compression none` selects those settings in
Churro without using WASM.

## 2. Shellcode generation parity

- [x] Diversify the entry prefix, stack setup, decoder registers and instruction
  order, trampoline, and junk forms per output while preserving the Windows x64
  calling convention; structural and variant tests pass.
- [x] Regenerate build-specific cipher/hash constants and API table ordering,
  with a manifest tying the Go serializer to both native loader images.
- [x] Add aPLib-compatible payload compression in the Go generator; Go tests
  round-trip packed data through `referenceDepack`, and Windows execution tests
  exercise the native C loader's depacker. Keep source provenance clear.
- [x] Support section-granular encrypted dispatch: the embedded MinGW images have
  six sections and 62 cross-section references per PEB variant. Four helper
  sections and the hash resolver are protected; `.text` stays resident. Static
  thunk and function-table tests pass.
- [x] Protect the hash-resolver section with synchronized entry and exit.
  A per-section transition lock and active-call count keep code decrypted
  until its final caller returns; static state tests and 4,096 emitted
  dispatcher variants pass. Windows contention execution is tracked below.
- [x] Vary N>1 dispatcher state registers, save order, inert instructions,
  and independent XOR-loop forms per output, matching Fritter's emitter axes.

## 3. Windows runtime coverage

- [x] Execute native EXE payloads, including thread mode and process-exit
  interception, in a bounded Windows test.
- [x] Execute managed EXE and DLL fixtures under CLR v4.
- [x] Execute managed EXE and DLL argument fixtures under CLR v4, including a
  quoted argument.
- [x] Execute managed EXE and DLL fixtures under CLR v2 on a runner with the
  .NET Framework 3.5 Windows feature installed.
- [x] Execute VBScript and JScript fixtures and verify their observable result.
- [x] Execute HTTP and HTTPS staged modules, including Basic Authentication and
  module-name handling, against a local test server.
- [x] Exercise native header overwrite/preserve, decoy-module loading, and
  host-image continuation with explicit markers.
- [x] Execute a custom rotated loader bundle through the public CLI on Windows.
- [x] Execute a 62-import native loader bundle with an added Advapi32 API
  through the public CLI on Windows.
- [x] Execute multiple randomized entry/decoder forms and aPLib loaders on
  Windows after the native dispatch change.
- [x] Execute `ExitProcess` and `ExitBlock` as bounded CLI cases with markers.
- [x] Execute native DLL loaders with `EntropyNone` and `EntropyNames`.
- [ ] Execute the legacy colon-option CLI and renamed native/managed EXE/DLL
  fixtures through the public CLI on Windows.
- [x] Execute a native DLL ANSI export argument containing non-ASCII text under
  Windows ANSI code page 1252 after the native loader rebuild.
- [x] Re-run the full Windows payload, CLR v2, custom-bundle, and clipboard
  checks at the commit containing the rebuilt native loader images.
- [x] Execute the deterministic two-thread protected hash-resolver test on
  Windows. Require observed active-call states 1, 2, 1, and 0, both native
  thread results, and restored ciphertext. Re-run four randomized host-image
  continuation loaders as full-loader stress at the same commit.
- [x] Stress public generator reuse, concurrency, output uniqueness, and
  staged-request immutability.
- [x] Repeat the generated Sliver session check after all loader changes and
  require a matching `SessionOpenedEvent` plus `GetSessions` entry.

## 4. Distribution

- [x] Implement the 11-target Go CLI release matrix with `CGO_ENABLED=0` and
  locally cross-build every target.
- [x] Build the Go CLI for Fritter's 11 host targets in CI with `CGO_ENABLED=0`.
- [x] Package CI archives with README, LICENSE, linked documentation, commit
  sidecars, and SHA-256 checksums; all 11 were independently checked.
- [ ] Publish and verify a tagged GitHub release from the final tested commit.

## Completion evidence

The complete [Windows Actions run 37572274717](https://github.com/sliverarmory/churro/actions/runs/37572274717)
passed 16 of 16 jobs at implementation commit
`cc555c781340499a904a885a6725f0fcefe06a7b`. Its
[Windows payload job](https://github.com/sliverarmory/churro/actions/runs/37572274717/job/112633584216)
passed 28 cases, including four fresh host-continuation loaders, non-ASCII
native DLL arguments on Windows ANSI code page 1252, custom imports,
CLR v4 arguments, entropy and exit modes. The dedicated
`TestWindowsProtectedHashConcurrent` check observed two callers in the
decrypted hash section, verified return values `0x11` and `0x22`, and
confirmed the original ciphertext was restored for two independent seeds.
The separate `TestWindowsClipboardCFTextReadback` check passed. The
[CLR v2 job](https://github.com/sliverarmory/churro/actions/runs/37572274717/job/112633329035)
passed managed EXE and DLL cases with and without quoted arguments. The
[native bundle build job](https://github.com/sliverarmory/churro/actions/runs/37572274717/job/112633329172)
compiled a 62-import image and generated a CLI loader from it.

The [Sliver session job](https://github.com/sliverarmory/churro/actions/runs/37572274717/job/112633328911)
observed `SessionOpenedEvent` ID
`91ab3bcb-b2a3-4094-bfef-d661397f73d1` on mTLS and confirmed the same
session ID, name, and PID in `GetSessions`. All 11 CLI archives from the run
were independently checked for SHA-256 and commit sidecars, embedded
`SOURCE_COMMIT`, nonempty binaries, and five packaged documents matching that
tested commit.
The sorted checksum-manifest SHA-256 is
`a42ccdb7c64f9a957b53245b2f22d3b954e25115292eb35b293f3be7e3631250`.

Tagged-release publication remains pending; no release tag or release assets
have been published.
