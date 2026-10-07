param(
    [string]$SliverRoot = "sliver",
    [string]$BuildDirectory = "build/windows-sliver"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$SliverPath = if ([System.IO.Path]::IsPathRooted($SliverRoot)) {
    (Resolve-Path $SliverRoot).Path
} else {
    (Resolve-Path (Join-Path $Root $SliverRoot)).Path
}
$BuildPath = if ([System.IO.Path]::IsPathRooted($BuildDirectory)) {
    $BuildDirectory
} else {
    Join-Path $Root $BuildDirectory
}
New-Item -ItemType Directory -Force -Path $BuildPath | Out-Null

$ZigCommand = Get-Command zig.exe -ErrorAction SilentlyContinue
if (-not $ZigCommand) {
    throw "Zig is required for the Sliver shared-library build"
}
$Zig = $ZigCommand.Source
$ZigVersion = & $Zig version
if ($LASTEXITCODE -ne 0 -or $ZigVersion -ne "0.17.0") {
    throw "Zig 0.17.0 is required for the Sliver shared-library build (found $ZigVersion)"
}
$env:CC = "`"$Zig`" cc -target x86_64-windows-gnu"
$env:CXX = "`"$Zig`" c++ -target x86_64-windows-gnu"
# Sliver chooses a compiler for the generated implant separately from the
# server's own Go build, using these 64-bit compiler overrides.
$env:SLIVER_CC_64 = $env:CC
$env:SLIVER_CXX_64 = $env:CXX
$env:CGO_ENABLED = "1"
$env:GOOS = "windows"
$env:GOARCH = "amd64"

function Invoke-Checked([string]$Label, [scriptblock]$Command) {
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

# This pinned Sliver version skips compiler selection when the server and
# implant are both Windows/amd64. Its Go build then receives an explicit empty
# CC value. Patch the CI checkout so generated shared libraries select Zig,
# and fail inside Sliver if the selected CC/CXX is not Zig.
$PinnedSliverCommit = "1c5d8ab5a928a5dbfbb00be3b5b1c3c2ffc68fb7"
$ActualSliverCommit = & git -C $SliverPath rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $ActualSliverCommit -ne $PinnedSliverCommit) {
    throw "Sliver checkout must be pinned to $PinnedSliverCommit (found $ActualSliverCommit)"
}
$CompilerSourceStatus = & git -C $SliverPath status --porcelain -- server/generate/binaries.go
if ($LASTEXITCODE -ne 0 -or $CompilerSourceStatus) {
    throw "Sliver compiler source has local changes; refusing to patch it"
}
$SliverZigPatch = Join-Path $Root "scripts/sliver-zig-cshared.patch"
Invoke-Checked "verify pinned Sliver Zig patch" {
    & git -C $SliverPath apply --ignore-space-change --check $SliverZigPatch
}
Invoke-Checked "apply pinned Sliver Zig patch" {
    & git -C $SliverPath apply --ignore-space-change $SliverZigPatch
}

$GeneratorExe = Join-Path $BuildPath "generate.exe"
$RunnerExe = Join-Path $BuildPath "run-shellcode.exe"
$ServerExe = Join-Path $BuildPath "sliver-server.exe"
$DriverExe = Join-Path $BuildPath "sliver-session.exe"

Push-Location $Root
try {
    Invoke-Checked "build Churro generator" {
        go build -o $GeneratorExe ./testdata/windows-e2e/generate
    }
    Invoke-Checked "build Windows shellcode runner" {
        go build -o $RunnerExe ./testdata/windows-e2e/run-shellcode
    }
}
finally {
    Pop-Location
}

Push-Location $SliverPath
try {
    Invoke-Checked "download Sliver build assets" {
        go run -buildvcs=false -mod=vendor ./util/cmd/assets
    }
    $env:CGO_ENABLED = "0"
    Invoke-Checked "build Sliver server" {
        go build -buildvcs=false -mod=vendor -trimpath -tags 'go_sqlite,server' -o $ServerExe ./server
    }
    $DriverSource = Join-Path $SliverPath "test/churro-e2e"
    New-Item -ItemType Directory -Force -Path $DriverSource | Out-Null
    Copy-Item (Join-Path $Root "testdata/windows-e2e/sliver-session/main.go") (Join-Path $DriverSource "main.go") -Force
    Invoke-Checked "build Sliver session driver" {
        go build -buildvcs=false -mod=vendor -trimpath -tags 'client,go_sqlite' -o $DriverExe ./test/churro-e2e
    }
}
finally {
    Pop-Location
}

$env:CGO_ENABLED = "1"
Invoke-Checked "Sliver session-open E2E" {
    & $DriverExe -server $ServerExe -generator $GeneratorExe -runner $RunnerExe -repo $SliverPath
}
