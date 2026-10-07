param(
    [string]$BuildDirectory = "build/windows-e2e"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
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
    throw "No x64 MinGW GCC was found"
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

Push-Location $Root
try {
    $GenerateExe = Join-Path $BuildPath "generate.exe"
    $RunnerExe = Join-Path $BuildPath "run-shellcode.exe"
    $LifecycleDll = Join-Path $BuildPath "native-lifecycle.dll"
    $ImportsDll = Join-Path $BuildPath "native-imports.dll"
    $GoDll = Join-Path $BuildPath "go-dll.dll"

    Invoke-Checked "build generator" { go build -o $GenerateExe ./testdata/windows-e2e/generate }
    Invoke-Checked "build runner" { go build -o $RunnerExe ./testdata/windows-e2e/run-shellcode }
    Invoke-Checked "build lifecycle DLL" {
        & $Gcc -shared -O2 -o $LifecycleDll ./testdata/windows-e2e/native-lifecycle.c
    }
    Invoke-Checked "build imports DLL" {
        & $Gcc -shared -O2 -o $ImportsDll ./testdata/windows-e2e/native-imports.c -luser32
    }
    Invoke-Checked "build Go DLL" {
        go build -buildmode=c-shared -o $GoDll ./testdata/windows-e2e/go-dll
    }

    $Cases = @(
        @{ Name = "native-lifecycle"; Dll = $LifecycleDll; Export = "Run";
           Markers = @{ ".tls" = "tls callback"; ".attach" = "dll process attach"; ".run" = "named export" } },
        @{ Name = "native-imports"; Dll = $ImportsDll; Export = "RunImports";
           Markers = @{ ".imports" = "relocations and imports" } },
        @{ Name = "go-dll"; Dll = $GoDll; Export = "HelloWorld";
           Markers = @{ ".go" = "hello from Go DLL" } }
    )

    foreach ($Case in $Cases) {
        for ($Attempt = 1; $Attempt -le 2; $Attempt++) {
            $Label = "$( $Case.Name )-$($Attempt.ToString('D2'))"
            $Loader = Join-Path $BuildPath "$Label.bin"
            $env:CHURRO_E2E_PREFIX = Join-Path $BuildPath $Label
            Write-Host "Generating and executing $Label"
            Invoke-Checked "generate $Label" {
                & $GenerateExe -dll $Case.Dll -export $Case.Export -out $Loader
            }
            if (-not (Test-Path $Loader -PathType Leaf) -or (Get-Item $Loader).Length -eq 0) {
                throw "$Label returned an empty loader"
            }
            Invoke-Checked "execute $Label" {
                & $RunnerExe -input $Loader -timeout 45s
            }
            foreach ($Suffix in $Case.Markers.Keys) {
                $Marker = "$($env:CHURRO_E2E_PREFIX)$Suffix"
                if (-not (Test-Path $Marker -PathType Leaf)) {
                    throw "$Label did not create $Marker"
                }
                $Actual = (Get-Content -Raw $Marker).Trim()
                if ($Actual -ne $Case.Markers[$Suffix]) {
                    throw "$Label marker $Marker contained '$Actual'"
                }
            }
            Write-Host "Passed $Label"
        }
    }
    Write-Host "All native and Go DLL loader tests passed"
}
finally {
    Remove-Item Env:CHURRO_E2E_PREFIX -ErrorAction SilentlyContinue
    Pop-Location
}
