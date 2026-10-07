param(
    [string]$BuildDirectory = "build/windows-clr-v2"
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

$ClrV2 = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v2.0.50727"
$Compiler = Join-Path $ClrV2 "csc.exe"
$Runtime = Join-Path $ClrV2 "mscorwks.dll"
foreach ($Required in @($Compiler, $Runtime)) {
    if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) {
        throw "CLR v2 prerequisite is missing after NET-Framework-Core installation: $Required"
    }
}

function Invoke-Checked([string]$Label, [scriptblock]$Command) {
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

function Invoke-CLRCase([string]$Label, [string]$InputPath, [string[]]$Options, [string]$Suffix, [string]$Expected) {
    $Loader = Join-Path $BuildPath "$Label.bin"
    $Prefix = Join-Path $BuildPath $Label
    $Marker = "$Prefix$Suffix"
    if (Test-Path -LiteralPath $Marker) {
        Remove-Item -LiteralPath $Marker -ErrorAction Stop
    }
    $env:CHURRO_E2E_PREFIX = $Prefix
    Invoke-Checked "generate $Label" {
        & $CliExe -input $InputPath -runtime v2.0.50727 -output $Loader @Options
    }
    if (-not (Test-Path -LiteralPath $Loader -PathType Leaf) -or (Get-Item -LiteralPath $Loader).Length -eq 0) {
        throw "$Label generated an empty loader"
    }

    $Start = [System.Diagnostics.ProcessStartInfo]::new($RunnerExe)
    $Start.UseShellExecute = $false
    $Start.RedirectStandardOutput = $true
    $Start.RedirectStandardError = $true
    $Start.ArgumentList.Add("-input")
    $Start.ArgumentList.Add($Loader)
    $Start.ArgumentList.Add("-timeout")
    $Start.ArgumentList.Add("45s")
    $Process = [System.Diagnostics.Process]::Start($Start)
    if ($null -eq $Process) {
        throw "could not start shellcode runner for $Label"
    }
    try {
        if (-not $Process.WaitForExit(60000)) {
            throw "$Label shellcode runner exceeded its 60-second outer deadline"
        }
        $Output = $Process.StandardOutput.ReadToEnd()
        $Errors = $Process.StandardError.ReadToEnd()
        Write-Host "$Label runner output: $Output $Errors"
        if ($Process.ExitCode -ne 0 -or $Output -notmatch "shellcode thread returned") {
            throw "$Label shellcode runner failed: exit=$($Process.ExitCode), output=$Output $Errors"
        }
    } finally {
        if (-not $Process.HasExited) {
            $Process.Kill($true)
            $Process.WaitForExit()
        }
        $Process.Dispose()
    }
    if (-not (Test-Path -LiteralPath $Marker -PathType Leaf)) {
        throw "$Label did not create its marker: $Marker"
    }
    $Actual = (Get-Content -LiteralPath $Marker -Raw).Trim()
    if ($Actual -ne $Expected) {
        throw "$Label marker was '$Actual', expected '$Expected'"
    }
    Write-Host "Passed $Label with CLR v2 marker '$Actual'"
}

$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"
$CliExe = Join-Path $BuildPath "churro-gen.exe"
$RunnerExe = Join-Path $BuildPath "run-shellcode.exe"
$ManagedExe = Join-Path $BuildPath "managed-v2-executable.exe"
$ManagedDll = Join-Path $BuildPath "managed-v2-library.dll"
$Source = Join-Path $Root "testdata/windows-e2e/managed.cs"

Push-Location $Root
try {
    Invoke-Checked "build public CLI" { go build -o $CliExe ./cmd/churro-gen }
    Invoke-Checked "build shellcode runner" { go build -o $RunnerExe ./testdata/windows-e2e/run-shellcode }
    Invoke-Checked "compile CLR v2 executable" {
        & $Compiler /nologo /target:exe /platform:x64 "/out:$ManagedExe" $Source
    }
    Invoke-Checked "compile CLR v2 library" {
        & $Compiler /nologo /target:library /platform:x64 "/out:$ManagedDll" $Source
    }
    Invoke-CLRCase -Label "managed-v2-executable" -InputPath $ManagedExe -Options @() `
        -Suffix ".managed-exe" -Expected "managed executable entry"
    Invoke-CLRCase -Label "managed-v2-executable-args" -InputPath $ManagedExe `
        -Options @("-args", '"quoted value" tail') `
        -Suffix ".managed-exe-args" -Expected "managed executable quoted arguments"
    Invoke-CLRCase -Label "managed-v2-library" -InputPath $ManagedDll `
        -Options @("-class", "ChurroE2E", "-method", "Run") `
        -Suffix ".managed-dll" -Expected "managed static method"
    Invoke-CLRCase -Label "managed-v2-library-args" -InputPath $ManagedDll `
        -Options @("-class", "ChurroE2E", "-method", "RunArgs", "-args", '"quoted value" tail') `
        -Suffix ".managed-dll-args" -Expected "managed static method quoted arguments"
} finally {
    Remove-Item Env:CHURRO_E2E_PREFIX -ErrorAction SilentlyContinue
    Pop-Location
}
