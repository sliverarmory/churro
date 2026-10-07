param(
    [string]$BuildDirectory = "build/windows-e2e",
    [string]$LoaderBundleDirectory = "",
    [string]$CustomImportBundleDirectory = ""
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
$CustomImportBundle = $null
if ($CustomImportBundleDirectory) {
    $CustomImportBundle = (Resolve-Path -LiteralPath $CustomImportBundleDirectory -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath (Join-Path $CustomImportBundle "bundle.json") -PathType Leaf)) {
        throw "Custom-import loader bundle manifest is missing from $CustomImportBundle"
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
        $Actual = Get-Content -Raw $Marker
        Write-Host "$Label marker $Marker = '$Actual'"
        if ($Actual -cne $Markers[$Suffix]) {
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

function Invoke-ExitBehaviorCase([string]$Label, [string]$ExitMode) {
    $Markers = @{ ".imports" = "relocations and imports" }
    $Loader = Join-Path $BuildPath "$Label.bin"
    $env:CHURRO_E2E_PREFIX = Join-Path $BuildPath $Label
    Clear-Markers $env:CHURRO_E2E_PREFIX $Markers
    Invoke-Checked "generate $Label" {
        & $CliExe -input $ImportsDll -method RunImports -exit $ExitMode -output $Loader
    }
    if (-not (Test-Path $Loader -PathType Leaf) -or (Get-Item $Loader).Length -eq 0) {
        throw "$Label returned an empty loader"
    }

    $StartInfo = [System.Diagnostics.ProcessStartInfo]::new($RunnerExe)
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    foreach ($Argument in @("-input", $Loader, "-timeout", "2s")) {
        [void]$StartInfo.ArgumentList.Add($Argument)
    }
    $ChildProcess = [System.Diagnostics.Process]::Start($StartInfo)
    if (-not $ChildProcess) {
        throw "$Label could not start the disposable shellcode runner"
    }
    try {
        if (-not $ChildProcess.WaitForExit(10000)) {
            throw "$Label runner exceeded the 10-second outer timeout"
        }
        $RunnerExitCode = $ChildProcess.ExitCode
        $StandardOutput = $ChildProcess.StandardOutput.ReadToEnd()
        $StandardError = $ChildProcess.StandardError.ReadToEnd()
        Write-Host "$Label runner exit=$RunnerExitCode stdout='$($StandardOutput.Trim())' stderr='$($StandardError.Trim())'"
        Assert-Markers $Label $env:CHURRO_E2E_PREFIX $Markers 0

        if ($ExitMode -eq "process") {
            if ($RunnerExitCode -ne 0 -or $StandardOutput.Contains("shellcode thread returned")) {
                throw "$Label did not terminate the runner process directly"
            }
        }
        elseif ($ExitMode -eq "block") {
            if ($RunnerExitCode -ne 1 -or
                -not $StandardError.Contains("shellcode thread did not return within 2s") -or
                $StandardOutput.Contains("shellcode thread returned")) {
                throw "$Label did not keep the shellcode thread blocked until the runner timeout"
            }
        }
        else {
            throw "unsupported exit-mode test: $ExitMode"
        }
    }
    finally {
        try {
            if (-not $ChildProcess.HasExited) {
                $ChildProcess.Kill($true)
                if (-not $ChildProcess.WaitForExit(5000)) {
                    throw "$Label runner could not be stopped"
                }
            }
        }
        finally {
            $ChildProcess.Dispose()
        }
    }
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
    $ManagedSource = Join-Path $Root "testdata/windows-e2e/managed.cs"
    Invoke-Checked "build managed EXE" {
        & $Csc /nologo /target:exe /platform:x64 "/out:$ManagedExe" $ManagedSource
    }
    Invoke-Checked "build managed DLL" {
        & $Csc /nologo /target:library /platform:x64 "/out:$ManagedDll" $ManagedSource
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
            ".entry" = "native executable entry"
            ".argv" = "native executable arguments"
        }
    }
    $RenamedNativeDll = Join-Path $BuildPath "native-dll-named-exe.exe"
    $RenamedNativeExe = Join-Path $BuildPath "native-exe-named-dll.dll"
    Copy-Item -LiteralPath $ImportsDll -Destination $RenamedNativeDll -Force
    Copy-Item -LiteralPath $NativeExe -Destination $RenamedNativeExe -Force
    Invoke-TestCase "native-dll-named-exe" {
        Invoke-CLILoaderCase -Label "native-dll-named-exe" -InputPath $RenamedNativeDll -Options @("-method", "RunImports") -Markers @{
            ".imports" = "relocations and imports"
        }
    }
    Invoke-TestCase "native-exe-named-dll" {
        Invoke-CLILoaderCase -Label "native-exe-named-dll" -InputPath $RenamedNativeExe -Options @("-thread", "-args", "churro-exe-argument") -Markers @{
            ".entry" = "native executable entry"
            ".argv" = "native executable arguments"
        }
    }
    Invoke-TestCase "legacy-colon-cli" {
        $Label = "legacy-colon-cli"
        $Loader = Join-Path $BuildPath "$Label.bin"
        $env:CHURRO_E2E_PREFIX = Join-Path $BuildPath $Label
        $Markers = @{ ".imports" = "relocations and imports" }
        Clear-Markers $env:CHURRO_E2E_PREFIX $Markers
        Invoke-Checked "generate $Label" {
            & $CliExe "stray-positional" ("-i:" + $ImportsDll) "-m:RunImports" ("-o:" + $Loader) "-entropy:none"
        }
        $RunnerOutput = @(& $RunnerExe -input $Loader -timeout 45s 2>&1)
        $RunnerExitCode = $LASTEXITCODE
        $RunnerOutput | ForEach-Object { Write-Host $_ }
        if ($RunnerOutput -notcontains "shellcode thread returned") {
            throw "$Label runner did not report shellcode completion"
        }
        Assert-Markers $Label $env:CHURRO_E2E_PREFIX $Markers $RunnerExitCode
    }
    Invoke-TestCase "legacy-attached-cli" {
        $Label = "legacy-attached-cli"
        $Loader = Join-Path $BuildPath "$Label.bin"
        $env:CHURRO_E2E_PREFIX = Join-Path $BuildPath $Label
        $Markers = @{ ".imports" = "relocations and imports" }
        Clear-Markers $env:CHURRO_E2E_PREFIX $Markers
        Invoke-Checked "generate $Label" {
            & $CliExe "stray-positional" ("-i" + $ImportsDll) "--methodRunImports" "-o:" $Loader "-e=" "none"
        }
        $RunnerOutput = @(& $RunnerExe -input $Loader -timeout 45s 2>&1)
        $RunnerExitCode = $LASTEXITCODE
        $RunnerOutput | ForEach-Object { Write-Host $_ }
        if ($RunnerOutput -notcontains "shellcode thread returned") {
            throw "$Label runner did not report shellcode completion"
        }
        Assert-Markers $Label $env:CHURRO_E2E_PREFIX $Markers $RunnerExitCode
    }
    Invoke-TestCase "native-args-ansi" {
        Invoke-CLILoaderCase -Label "native-args-ansi" -InputPath $ImportsDll -Options @("-method", "RunArgsA", "-args", "churro-ansi-argument") -Markers @{
            ".args-ansi" = "ANSI argument received"
        }
    }
    Add-Type -Namespace ChurroE2E -Name NativeCodePage -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern uint GetACP();
'@
    $AnsiCodePage = [ChurroE2E.NativeCodePage]::GetACP()
    if ($AnsiCodePage -eq 65001) {
        throw "native-args-ansi-nonascii requires a non-UTF-8 Windows ANSI code page"
    }
    Write-Host "Testing non-ASCII native export argument with ANSI code page $AnsiCodePage"
    Invoke-TestCase "native-args-ansi-nonascii" {
        Invoke-CLILoaderCase -Label "native-args-ansi-nonascii" -InputPath $ImportsDll -Options @("-method", "RunArgsACP", "-args", "caf$([char]0x00e9)") -Markers @{
            ".args-acp" = "ANSI code page argument received"
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
    Invoke-TestCase "managed-executable-args" {
        Invoke-CLILoaderCase -Label "managed-executable-args" -InputPath $ManagedExe -Options @("-args", '"quoted value" tail') -Markers @{
            ".managed-exe-args" = "managed executable quoted arguments"
        }
    }
    Invoke-TestCase "managed-library" {
        Invoke-CLILoaderCase -Label "managed-library" -InputPath $ManagedDll -Options @("-class", "ChurroE2E", "-method", "Run") -Markers @{
            ".managed-dll" = "managed static method"
        }
    }
    Invoke-TestCase "managed-library-args" {
        Invoke-CLILoaderCase -Label "managed-library-args" -InputPath $ManagedDll -Options @("-class", "ChurroE2E", "-method", "RunArgs", "-args", '"quoted value" tail') -Markers @{
            ".managed-dll-args" = "managed static method quoted arguments"
        }
    }
    $RenamedManagedDll = Join-Path $BuildPath "managed-dll-named-exe.exe"
    $RenamedManagedExe = Join-Path $BuildPath "managed-exe-named-dll.dll"
    Copy-Item -LiteralPath $ManagedDll -Destination $RenamedManagedDll -Force
    Copy-Item -LiteralPath $ManagedExe -Destination $RenamedManagedExe -Force
    Invoke-TestCase "managed-dll-named-exe" {
        Invoke-CLILoaderCase -Label "managed-dll-named-exe" -InputPath $RenamedManagedDll -Options @("-class", "ChurroE2E", "-method", "Run") -Markers @{
            ".managed-dll" = "managed static method"
        }
    }
    Invoke-TestCase "managed-exe-named-dll" {
        Invoke-CLILoaderCase -Label "managed-exe-named-dll" -InputPath $RenamedManagedExe -Options @() -Markers @{
            ".managed-exe" = "managed executable entry"
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
    Invoke-TestCase "native-entropy-none" {
        Invoke-CLILoaderCase -Label "native-entropy-none" -InputPath $ImportsDll -Options @("-method", "RunImports", "-entropy", "none") -Markers @{
            ".imports" = "relocations and imports"
        }
    }
    Invoke-TestCase "native-entropy-names" {
        Invoke-CLILoaderCase -Label "native-entropy-names" -InputPath $ImportsDll -Options @("-method", "RunImports", "-entropy", "names") -Markers @{
            ".imports" = "relocations and imports"
        }
    }
    Invoke-TestCase "exit-process" {
        Invoke-ExitBehaviorCase "exit-process" "process"
    }
    Invoke-TestCase "exit-block" {
        Invoke-ExitBehaviorCase "exit-block" "block"
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
    if ($CustomImportBundle) {
        Invoke-TestCase "custom-api-import-bundle" {
            Invoke-CLILoaderCase -Label "custom-api-import-bundle" -InputPath $ImportsDll -Options @(
                "-method", "RunImports", "-loader-bundle", $CustomImportBundle
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
        $HostRVAHex = "0x{0:x}" -f [uint32]::Parse($HostRVA)
        $HostMarkers = @{
            ".continued" = "host thread continued"
            ".imports" = "relocations and imports"
        }
        # Fresh loaders and processes exercise the two concurrent hash
        # resolver paths under several randomized dispatcher layouts.
        # Scheduler overlap is probabilistic; the Windows dispatcher test
        # checks an observed same-section overlap deterministically.
        for ($Attempt = 1; $Attempt -le 4; $Attempt++) {
            $Label = "host-continuation-$($Attempt.ToString('D2'))"
            $Loader = Join-Path $BuildPath "$Label.bin"
            $env:CHURRO_E2E_PREFIX = Join-Path $BuildPath $Label
            Clear-Markers $env:CHURRO_E2E_PREFIX $HostMarkers
            Invoke-Checked "generate $Label loader through public CLI" {
                & $CliExe -input $ImportsDll -method RunImports -fork $HostRVAHex -output $Loader
            }
            & $ContinuationExe --loader $Loader
            $RunnerExitCode = $LASTEXITCODE
            Assert-Markers $Label $env:CHURRO_E2E_PREFIX $HostMarkers $RunnerExitCode
        }
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
