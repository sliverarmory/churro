param(
    [string]$BuildDirectory = "build/windows-e2e",
    [string]$LoaderBundleDirectory = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $false

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BuildPath = if ([System.IO.Path]::IsPathRooted($BuildDirectory)) {
    $BuildDirectory
} else {
    Join-Path $Root $BuildDirectory
}
New-Item -ItemType Directory -Force -Path $BuildPath | Out-Null
$RotatedBundle = $null
if ($LoaderBundleDirectory) {
    $RotatedBundle = (Resolve-Path -LiteralPath $LoaderBundleDirectory -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath (Join-Path $RotatedBundle "bundle.json") -PathType Leaf)) {
        throw "Rotated loader bundle manifest is missing from $RotatedBundle"
    }
}

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

function Assert-Markers(
    [string]$Label,
    [string]$Prefix,
    [System.Collections.IDictionary]$Markers,
    [int]$RunnerExitCode
) {
    $Problems = @()
    if ($RunnerExitCode -ne 0) {
        $Problems += "runner exited with code $RunnerExitCode"
    }
    foreach ($Suffix in ($Markers.Keys | Sort-Object)) {
        $Marker = "$Prefix$Suffix"
        if (-not (Test-Path $Marker -PathType Leaf)) {
            Write-Host "$Label missing marker $Marker"
            $Problems += "missing $Marker"
            continue
        }
        $Actual = (Get-Content -Raw $Marker).Trim()
        Write-Host "$Label marker $Marker = '$Actual'"
        if ($Actual -ne $Markers[$Suffix]) {
            $Problems += "unexpected content in $Marker"
        }
    }
    if ($Problems.Count -ne 0) {
        $Observed = @(Get-ChildItem -Path "$Prefix.*" -File -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty FullName)
        throw "$Label failed: $($Problems -join '; '); observed: $($Observed -join ', ')"
    }
}

function Clear-Markers([string]$Prefix, [System.Collections.IDictionary]$Markers) {
    foreach ($Suffix in $Markers.Keys) {
        $Marker = "$Prefix$Suffix"
        if (Test-Path -LiteralPath $Marker) {
            Remove-Item -LiteralPath $Marker -ErrorAction Stop
        }
    }
}

$script:Failures = @()

function Invoke-TestCase([string]$Label, [scriptblock]$Body) {
    try {
        & $Body
        Write-Host "Passed $Label"
    }
    catch {
        $Message = $_.Exception.Message
        Write-Host "FAILED $Label`: $Message"
        $script:Failures += "$Label`: $Message"
    }
}

function Invoke-CLILoaderCase(
    [string]$Label,
    [string]$InputPath,
    [string[]]$Options,
    [System.Collections.IDictionary]$Markers
) {
    $Loader = Join-Path $BuildPath "$Label.bin"
    $env:CHURRO_E2E_PREFIX = Join-Path $BuildPath $Label
    Clear-Markers $env:CHURRO_E2E_PREFIX $Markers
    Write-Host "Generating and executing $Label through public churro-gen CLI"
    Invoke-Checked "generate $Label" {
        & $CliExe -input $InputPath -output $Loader @Options
    }
    if (-not (Test-Path $Loader -PathType Leaf) -or (Get-Item $Loader).Length -eq 0) {
        throw "$Label returned an empty loader"
    }
    $RunnerOutput = @(& $RunnerExe -input $Loader -timeout 45s 2>&1)
    $RunnerExitCode = $LASTEXITCODE
    $RunnerOutput | ForEach-Object { Write-Host $_ }
    if ($RunnerOutput -notcontains "shellcode thread returned") {
        throw "$Label runner did not report shellcode completion"
    }
    Assert-Markers $Label $env:CHURRO_E2E_PREFIX $Markers $RunnerExitCode
}

Push-Location $Root
try {
    $GenerateExe = Join-Path $BuildPath "generate.exe"
    $CliExe = Join-Path $BuildPath "churro-gen.exe"
    $RunnerExe = Join-Path $BuildPath "run-shellcode.exe"
    $LifecycleDll = Join-Path $BuildPath "native-lifecycle.dll"
    $ImportsDll = Join-Path $BuildPath "native-imports.dll"
    $GoDll = Join-Path $BuildPath "go-dll.dll"
    $NativeExe = Join-Path $BuildPath "native-executable.exe"
    $ManagedExe = Join-Path $BuildPath "managed-executable.exe"
    $ManagedDll = Join-Path $BuildPath "managed-library.dll"
    $StagedExe = Join-Path $BuildPath "staged.exe"
    $ContinuationExe = Join-Path $BuildPath "host-continuation.exe"

    Invoke-Checked "build generator" { go build -o $GenerateExe ./testdata/windows-e2e/generate }
    Invoke-Checked "build public CLI" { go build -o $CliExe ./cmd/churro-gen }
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
    Invoke-Checked "build native EXE" {
        & $Gcc -O2 -o $NativeExe ./testdata/windows-e2e/native-executable.c
    }
    Invoke-Checked "build host continuation runner" {
        & $Gcc -O2 -o $ContinuationExe ./testdata/windows-e2e/host-continuation.c
    }
    Invoke-Checked "build staged HTTP and HTTPS test" {
        go build -o $StagedExe ./testdata/windows-e2e/staged
    }
    $Csc = @(
        (Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
        (Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe")
    ) | Where-Object { Test-Path $_ -PathType Leaf } | Select-Object -First 1
    if (-not $Csc) {
        $CscCommand = Get-Command csc.exe -ErrorAction SilentlyContinue
        if ($CscCommand) { $Csc = $CscCommand.Source }
    }
    if (-not $Csc) {
        throw "The .NET Framework 4 C# compiler was not found"
    }
    Invoke-Checked "build managed EXE" {
        & $Csc /nologo /target:exe /platform:x64 "/out:$ManagedExe" ./testdata/windows-e2e/managed.cs
    }
    Invoke-Checked "build managed DLL" {
        & $Csc /nologo /target:library /platform:x64 "/out:$ManagedDll" ./testdata/windows-e2e/managed.cs
    }

    Invoke-TestCase "go-dll-cli" {
        Invoke-CLILoaderCase -Label "go-dll-cli" -InputPath $GoDll -Options @("-method", "HelloWorld") -Markers @{
            ".go" = "hello from Go DLL"
        }
    }

    $Cases = @(
        @{ Name = "go-dll"; Dll = $GoDll; Export = "HelloWorld";
           Markers = @{ ".go" = "hello from Go DLL" } },
        @{ Name = "native-imports"; Dll = $ImportsDll; Export = "RunImports";
           Markers = @{ ".imports" = "relocations and imports" } },
        @{ Name = "native-lifecycle"; Dll = $LifecycleDll; Export = "Run";
           Markers = @{ ".tls" = "tls callback"; ".attach" = "dll process attach"; ".run" = "named export" } }
    )

    foreach ($Case in $Cases) {
        for ($Attempt = 1; $Attempt -le 2; $Attempt++) {
            $Label = "$( $Case.Name )-$($Attempt.ToString('D2'))"
            Invoke-TestCase $Label {
                $Loader = Join-Path $BuildPath "$Label.bin"
                $Headers = if ($Attempt -eq 1) { "overwrite" } else { "preserve" }
                $env:CHURRO_E2E_PREFIX = Join-Path $BuildPath $Label
                Clear-Markers $env:CHURRO_E2E_PREFIX $Case.Markers
                Write-Host "Generating and executing $Label (headers=$Headers)"
                Invoke-Checked "generate $Label" {
                    & $GenerateExe -dll $Case.Dll -export $Case.Export -headers $Headers -out $Loader
                }
                if (-not (Test-Path $Loader -PathType Leaf) -or (Get-Item $Loader).Length -eq 0) {
                    throw "$Label returned an empty loader"
                }
                $RunnerOutput = @(& $RunnerExe -input $Loader -timeout 45s 2>&1)
                $RunnerExitCode = $LASTEXITCODE
                $RunnerOutput | ForEach-Object { Write-Host $_ }
                if ($RunnerOutput -notcontains "shellcode thread returned") {
                    throw "$Label runner did not report shellcode completion"
                }
                Assert-Markers $Label $env:CHURRO_E2E_PREFIX $Case.Markers $RunnerExitCode
            }
        }
    }

    Invoke-TestCase "native-executable" {
        Invoke-CLILoaderCase -Label "native-executable" -InputPath $NativeExe -Options @("-thread", "-args", "churro-exe-argument") -Markers @{
            ".exe" = "native executable entry"
            ".argv" = "native executable arguments"
        }
    }
    Invoke-TestCase "native-args-ansi" {
        Invoke-CLILoaderCase -Label "native-args-ansi" -InputPath $ImportsDll -Options @("-method", "RunArgsA", "-args", "churro-ansi-argument") -Markers @{
            ".args-ansi" = "ANSI argument received"
        }
    }
    Invoke-TestCase "native-args-unicode" {
        Invoke-CLILoaderCase -Label "native-args-unicode" -InputPath $ImportsDll -Options @("-method", "RunArgsW", "-args", "churro-wide-argument", "-unicode") -Markers @{
            ".args-wide" = "Unicode argument received"
        }
    }
    Invoke-TestCase "managed-executable" {
        Invoke-CLILoaderCase -Label "managed-executable" -InputPath $ManagedExe -Options @() -Markers @{
            ".managed-exe" = "managed executable entry"
        }
    }
    Invoke-TestCase "managed-library" {
        Invoke-CLILoaderCase -Label "managed-library" -InputPath $ManagedDll -Options @("-class", "ChurroE2E", "-method", "Run") -Markers @{
            ".managed-dll" = "managed static method"
        }
    }
    Invoke-TestCase "vbscript" {
        Invoke-CLILoaderCase -Label "vbscript" -InputPath (Join-Path $Root "testdata/windows-e2e/hello.vbs") -Options @() -Markers @{
            ".vbs" = "VBScript executed"
        }
    }
    Invoke-TestCase "jscript" {
        Invoke-CLILoaderCase -Label "jscript" -InputPath (Join-Path $Root "testdata/windows-e2e/hello.js") -Options @() -Markers @{
            ".js" = "JScript executed"
        }
    }
    Invoke-TestCase "native-decoy" {
        $Decoy = Join-Path $env:WINDIR "System32\kernel32.dll"
        if (-not (Test-Path $Decoy -PathType Leaf)) {
            throw "native decoy module is missing: $Decoy"
        }
        Invoke-CLILoaderCase -Label "native-decoy" -InputPath $ImportsDll -Options @("-method", "RunImports", "-decoy", $Decoy) -Markers @{
            ".imports" = "relocations and imports"
        }
    }
    Invoke-TestCase "native-aplib" {
        Invoke-CLILoaderCase -Label "native-aplib" -InputPath $ImportsDll -Options @("-method", "RunImports", "-compression", "aplib") -Markers @{
            ".imports" = "relocations and imports"
        }
    }
    Invoke-TestCase "custom-loader-bundle" {
        Invoke-CLILoaderCase -Label "custom-loader-bundle" -InputPath $ImportsDll -Options @(
            "-method", "RunImports", "-loader-bundle", (Join-Path $Root "internal/assets")
        ) -Markers @{
            ".imports" = "relocations and imports"
        }
    }
    if ($RotatedBundle) {
        Invoke-TestCase "rotated-loader-bundle" {
            Invoke-CLILoaderCase -Label "rotated-loader-bundle" -InputPath $ImportsDll -Options @(
                "-method", "RunImports", "-loader-bundle", $RotatedBundle
            ) -Markers @{
                ".imports" = "relocations and imports"
            }
        }
    }
    Invoke-TestCase "authenticated HTTP and HTTPS staging" {
        Invoke-Checked "execute staged loaders" {
            & $StagedExe -dll $ImportsDll -runner $RunnerExe -out-dir $BuildPath
        }
    }
    Invoke-TestCase "host-continuation" {
        $HostRVA = & $ContinuationExe --rva
        if ($LASTEXITCODE -ne 0 -or $HostRVA -notmatch '^[0-9]+$') {
            throw "query host continuation RVA failed: $HostRVA"
        }
        $Label = "host-continuation"
        $Loader = Join-Path $BuildPath "$Label.bin"
        $env:CHURRO_E2E_PREFIX = Join-Path $BuildPath $Label
        $HostRVAHex = "0x{0:x}" -f [uint32]::Parse($HostRVA)
        $HostMarkers = @{
            ".continued" = "host thread continued"
            ".imports" = "relocations and imports"
        }
        Clear-Markers $env:CHURRO_E2E_PREFIX $HostMarkers
        Invoke-Checked "generate host continuation loader through public CLI" {
            & $CliExe -input $ImportsDll -method RunImports -fork $HostRVAHex -output $Loader
        }
        & $ContinuationExe --loader $Loader
        $RunnerExitCode = $LASTEXITCODE
        Assert-Markers $Label $env:CHURRO_E2E_PREFIX $HostMarkers $RunnerExitCode
    }
    if ($script:Failures.Count -ne 0) {
        throw "$($script:Failures.Count) Windows E2E cases failed: $($script:Failures -join ' | ')"
    }
    Write-Host "All Windows loader cases passed"
}
finally {
    Remove-Item Env:CHURRO_E2E_PREFIX -ErrorAction SilentlyContinue
    Pop-Location
}
