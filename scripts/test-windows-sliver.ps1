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

$GccCandidates = @(
    $env:CC,
    "C:\msys64\mingw64\bin\gcc.exe",
    "C:\msys64\ucrt64\bin\gcc.exe",
    "C:\mingw64\bin\gcc.exe"
) | Where-Object { $_ -and (Test-Path $_ -PathType Leaf) }
$Gcc = $GccCandidates | Select-Object -First 1
if (-not $Gcc) {
    $Command = Get-Command gcc.exe -ErrorAction SilentlyContinue
    if ($Command) { $Gcc = $Command.Source }
}
if (-not $Gcc) {
    throw "No x64 MinGW GCC was found for the Sliver shared-library build"
}
$env:PATH = "$(Split-Path $Gcc);$env:PATH"
$env:CC = $Gcc
$env:CGO_ENABLED = "1"
$env:GOOS = "windows"
$env:GOARCH = "amd64"

function Invoke-Checked([string]$Label, [scriptblock]$Command) {
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
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
