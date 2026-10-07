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
on `feat/fritter-parity`. Local `go test ./...`, `go test -race ./...`,
`go vet ./...`, all 11 cross-builds, and a byte-for-byte pinned loader
rebuild passed. Windows execution evidence is recorded below.

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

The CLI does not copy Base64 output to the Windows clipboard automatically.
Fritter does this as a convenience side effect; Churro writes the same encoded
output to its selected file.

## 2. Shellcode generation parity

- [x] Diversify the entry prefix, stack setup, decoder registers and instruction
  order, trampoline, and junk forms per output while preserving the Windows x64
  calling convention; structural and variant tests pass.
- [x] Regenerate build-specific cipher/hash constants and API table ordering,
  with a manifest tying the Go serializer to both native loader images.
- [x] Add aPLib-compatible payload compression in the Go generator; a native C
  depacker fixture and Go round-trip tests pass. Keep source provenance clear.
- [x] Support per-function encrypted dispatch: the embedded MinGW images have
  six sections and 61 cross-section references per PEB variant. Four helper
  sections are protected; `.text` and the hash section stay resident for
  host-continuation concurrency. Static thunk and function-table tests pass.
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

The implementation commit is `dfff600419af817798894ee9a7df570b60225b93`.
Its [Windows payload job](https://github.com/sliverarmory/churro/actions/runs/37567275171/job/112617978831)
passed 27 cases, including the added-import native bundle, CLR v4 arguments,
entropy and exit modes. The [CLR v2 job](https://github.com/sliverarmory/churro/actions/runs/37567275171/job/112617751451)
passed managed EXE and DLL cases with and without quoted arguments. The
[native bundle build job](https://github.com/sliverarmory/churro/actions/runs/37567275171/job/112617751315)
compiled the 62-import image and generated a CLI loader from it. All 11 CLI
archives from this run were checked independently: archive SHA-256 sidecars,
commit sidecars, embedded `SOURCE_COMMIT`, nonempty binaries, and the five
packaged documentation files matched the implementation commit. The sorted
checksum-manifest SHA-256 is
`0fd26a096eb5e0f02962be0978ca6e2c0a37aa7876df653c6f96193f08586b41`.

The complete [Windows Actions run 37567275171](https://github.com/sliverarmory/churro/actions/runs/37567275171)
passed 16 of 16 jobs at the implementation commit. Its
[Sliver session job](https://github.com/sliverarmory/churro/actions/runs/37567275171/job/112617751554)
observed `SessionOpenedEvent` ID
`1a2b074b-50e3-4df6-a3b9-de131552222b` on mTLS and confirmed the same
session in `GetSessions`.

Tagged-release publication remains pending; no release tag or release assets
have been published.
