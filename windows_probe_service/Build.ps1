$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

if ($env:OS -ne 'Windows_NT') {
    throw 'Windows EXE builds must run on Windows. PyInstaller does not cross-compile from macOS or Linux.'
}

$pythonCheck = "import sys, sysconfig; assert sys.version_info >= (3,11) and sys.maxsize > 2**32 and sysconfig.get_platform() == 'win-amd64', 'A 64-bit Windows x64 Python 3.11+ is required'"
function Find-BuildPython {
    foreach ($candidate in @(
        [pscustomobject]@{ Program = 'python'; Arguments = @() },
        [pscustomobject]@{ Program = 'py'; Arguments = @('-3') }
    )) {
        if (-not (Get-Command $candidate.Program -ErrorAction SilentlyContinue)) { continue }
        try {
            $program = [string]$candidate.Program
            $arguments = @($candidate.Arguments)
            & $program @arguments -c $pythonCheck 2>$null
            if ($LASTEXITCODE -eq 0) { return $candidate }
        } catch { }
    }
    throw 'Build machine: install Windows x64 Python 3.11+ (3.12 recommended). End users of SOARProbe.exe do not need Python.'
}

$python = Find-BuildPython
$program = [string]$python.Program
$pythonArguments = @($python.Arguments)
$buildPython = Join-Path $PSScriptRoot '.build-venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $buildPython)) {
    & $program @pythonArguments -m venv .build-venv
    if ($LASTEXITCODE -ne 0) { throw 'Creating the isolated build environment failed.' }
}
& $buildPython -c $pythonCheck
if ($LASTEXITCODE -ne 0) { throw 'The existing .build-venv is incompatible. Rename it, then rebuild with Windows x64 Python.' }
# Clean only this project's isolated build environment when upgrading an older
# build. These removed packages must not leak into either release layout.
& $buildPython -m pip uninstall -y fastapi pydantic pydantic_core
if ($LASTEXITCODE -ne 0) { throw 'Removing obsolete dependencies from .build-venv failed.' }
& $buildPython -m pip install --disable-pip-version-check -r requirements-build.txt
if ($LASTEXITCODE -ne 0) { throw 'Installing build dependencies failed. Check access to the configured Python package index.' }
& $buildPython -m pip check
if ($LASTEXITCODE -ne 0) { throw 'Build dependencies are inconsistent.' }
& $buildPython -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { throw 'Offline service tests failed; EXE generation stopped.' }

function Test-BundledExecutable {
    param([string]$exePath, [string]$Layout)
    # Validate that the artifact is a Windows x64 PE, not a renamed host binary.
    $stream = [System.IO.File]::OpenRead($exePath)
    $reader = New-Object System.IO.BinaryReader($stream)
    try {
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw 'Output is not a Windows executable (MZ header missing).' }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 64 -or $peOffset -gt ($stream.Length - 26)) { throw 'Output has an invalid PE header offset.' }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw 'Output has an invalid PE signature.' }
        if ($reader.ReadUInt16() -ne 0x8664) { throw 'Output is not Windows x64.' }
        $stream.Position = $peOffset + 24
        if ($reader.ReadUInt16() -ne 0x020B) { throw 'Output is not a PE32+ executable.' }
    } finally { $reader.Dispose() }

    $selfTestLines = @(& $exePath --self-test)
    if ($LASTEXITCODE -ne 0) { throw 'The generated EXE failed its offline self-test.' }
    $selfTest = ($selfTestLines -join "`n") | ConvertFrom-Json
    if ($selfTest.status -ne 'ok' -or $selfTest.frozen -ne $true -or $selfTest.bundleLayout -ne $Layout) { throw 'The EXE did not confirm bundled runtime/resources in its self-test.' }
    if ($selfTest.httpStack -ne 'starlette' -or $selfTest.validationImplementation -ne 'python' -or $selfTest.pydanticCoreBundled -isnot [bool] -or $selfTest.pydanticCoreBundled -ne $false) { throw 'The EXE did not confirm the Starlette/Python implementation without pydantic_core.' }
    if ($selfTest.customDnsServers -ne $true -or ($selfTest.dnsServers -join ',') -ne '8.8.8.8,223.5.5.5') { throw 'The EXE self-test did not confirm configurable DNS support.' }

    if ($Layout -eq 'onedir') {
        $expectedRuntimeRoot = [System.IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $exePath) '_internal'))
        $actualRuntime = [System.IO.Path]::GetFullPath([string]$selfTest.nativeDependencies.pythonRuntime)
        $actualRuntimeRoot = [System.IO.Path]::GetDirectoryName($actualRuntime)
        if (-not $actualRuntimeRoot.Equals($expectedRuntimeRoot, [System.StringComparison]::OrdinalIgnoreCase) -or [System.IO.Path]::GetFileName($actualRuntime) -notmatch '^python3\d+(?:t|_d)?\.dll$' -or -not (Test-Path -LiteralPath $actualRuntime -PathType Leaf)) { throw 'Portable service did not load a versioned Python runtime DLL from its fixed _internal folder.' }
        $runtimeSignature = Get-AuthenticodeSignature -FilePath $actualRuntime
        Write-Host ('Portable PythonRuntime signature status: ' + $runtimeSignature.Status)
    }

    # Smoke the actual bundled ASGI server on loopback without target network I/O.
    $smokeDir = Join-Path ([System.IO.Path]::GetTempPath()) ('soar exe smoke ' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $smokeDir | Out-Null
    $process = $null
    try {
        & $exePath --init-config --data-dir $smokeDir
        if ($LASTEXITCODE -ne 0) { throw 'The EXE failed to initialize its isolated smoke configuration.' }
        # Reserve a candidate loopback port so an already-running user service is
        # never stopped or reused by this build check.
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        try {
            $listener.Start()
            $smokePort = $listener.LocalEndpoint.Port
        } finally { $listener.Stop() }
        $smokeConfigPath = Join-Path $smokeDir 'config.json'
        $smokeConfig = Get-Content -LiteralPath $smokeConfigPath -Raw | ConvertFrom-Json
        $smokeConfig.port = $smokePort
        [System.IO.File]::WriteAllText($smokeConfigPath, ($smokeConfig | ConvertTo-Json), [System.Text.UTF8Encoding]::new($false))
        $smokeUrl = 'http://127.0.0.1:' + $smokePort
        $arguments = '--no-interactive --data-dir "' + $smokeDir + '"'
        $process = Start-Process -FilePath $exePath -ArgumentList $arguments -PassThru -WindowStyle Hidden -WorkingDirectory $smokeDir -RedirectStandardOutput (Join-Path $smokeDir 'stdout.log') -RedirectStandardError (Join-Path $smokeDir 'stderr.log')
        $health = $null
        for ($attempt = 0; $attempt -lt 40; $attempt++) {
            $process.Refresh()
            if ($process.HasExited) { throw 'The bundled service exited during startup. See EXE smoke stderr.' }
            try {
                $health = Invoke-RestMethod -Uri ($smokeUrl + '/health') -TimeoutSec 1
                if ($health.status -eq 'ok' -and $health.service -eq 'soar-network-probe') { break }
            } catch { }
            Start-Sleep -Milliseconds 250
        }
        if ($null -eq $health -or $health.status -ne 'ok' -or $health.platform -ne 'windows' -or $health.ipv4Only -ne $true) { throw 'The bundled Windows IPv4 service did not become healthy.' }
        if ($health.domainNslookup -ne $true -or $health.domainPing -ne $true -or $health.domainDnsFallback -ne $true -or ($health.domainDefaultPorts -join ',') -ne '80,443') { throw 'The bundled service is missing domain DNS fallback or default TCP ports.' }
        if ($health.customDnsServers -ne $true -or ($health.dnsServers -join ',') -ne '8.8.8.8,223.5.5.5') { throw 'The bundled service is missing configurable DNS capability.' }
        $auth = Invoke-RestMethod -Uri ($smokeUrl + '/v1/auth-check') -Headers @{ Authorization = 'Bearer ' + $smokeConfig.token } -TimeoutSec 3
        if ($auth.status -ne 'ok' -or $auth.apiVersion -ne 1) { throw 'The bundled service failed its authenticated check.' }
        # Exercise the new frozen API schema using a special address that the
        # policy must skip. No DNS, Ping or TCP target traffic is permitted here.
        $probeHeaders = @{ Authorization = 'Bearer ' + $smokeConfig.token }
        $probeBody = @{ queryId = 'ci-dns-schema'; targets = @(@{ id = 'filtered'; host = '0.0.0.0'; port = $null }); dnsServers = @('192.168.1.53') } | ConvertTo-Json -Depth 6
        $probeJob = Invoke-RestMethod -Uri ($smokeUrl + '/v1/probes') -Method Post -ContentType 'application/json' -Body $probeBody -Headers $probeHeaders -TimeoutSec 3
        if ($probeJob.queryId -ne 'ci-dns-schema' -or $probeJob.total -ne 1 -or [string]::IsNullOrWhiteSpace($probeJob.jobId)) { throw 'The bundled service did not accept a valid custom DNS request.' }
        $probeResult = $null
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            $probeResult = Invoke-RestMethod -Uri ($smokeUrl + '/v1/probes/' + $probeJob.jobId + '?after=0') -Headers $probeHeaders -TimeoutSec 3
            if ($probeResult.status -eq 'completed') { break }
            Start-Sleep -Milliseconds 100
        }
        if ($probeResult.status -ne 'completed' -or $probeResult.completed -ne 1 -or @($probeResult.results).Count -ne 1 -or $probeResult.results[0].ping[0].status -ne 'skipped_private' -or @($probeResult.results[0].tcp).Count -ne 0) { throw 'The custom DNS schema smoke did not skip its special IPv4 target.' }
        Write-Host 'Verified custom DNS API: configuration accepted; special IPv4 target skipped without probe I/O.'
    } catch {
        $failure = $_
        $errorFile = Join-Path $smokeDir 'stderr.log'
        if (Test-Path -LiteralPath $errorFile) { Get-Content -LiteralPath $errorFile -Tail 30 | Write-Host }
        throw $failure
    } finally {
        if ($null -ne $process) {
            $process.Refresh()
            if (-not $process.HasExited) {
                # Onefile bootloaders may have a child process. Stop only the tree
                # created by this smoke, leaving any user instance untouched.
                try { & "$env:SystemRoot\System32\taskkill.exe" /PID $process.Id /T /F 2>&1 | Out-Null } catch { }
                $process.Refresh()
                if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
                $process.WaitForExit(5000) | Out-Null
            }
            $process.Dispose()
        }
        Remove-Item -LiteralPath $smokeDir -Recurse -Force -ErrorAction SilentlyContinue
    }

}

function Build-Layout {
    param([string]$Layout)
    $previousLayout = $env:SOAR_BUILD_LAYOUT
    try {
        $env:SOAR_BUILD_LAYOUT = $Layout
        & $buildPython -m PyInstaller --noconfirm --clean --distpath dist --workpath ('.build-cache-' + $Layout) SOARProbe.spec
        if ($LASTEXITCODE -ne 0) { throw ('PyInstaller failed for layout: ' + $Layout) }
    } finally {
        if ($null -eq $previousLayout) { Remove-Item Env:\SOAR_BUILD_LAYOUT -ErrorAction SilentlyContinue }
        else { $env:SOAR_BUILD_LAYOUT = $previousLayout }
    }
}

Build-Layout 'onefile'
$exePath = Join-Path $PSScriptRoot 'dist\SOARProbe.exe'
if (-not (Test-Path -LiteralPath $exePath)) { throw 'The expected SOARProbe.exe was not created.' }
Test-BundledExecutable $exePath 'onefile'

# Keep the existing single-file download for unrestricted computers.
$hash = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256).Hash.ToLowerInvariant()
$checksumPath = Join-Path $PSScriptRoot 'dist\SHA256SUMS.txt'
[System.IO.File]::WriteAllText($checksumPath, $hash + '  SOARProbe.exe' + "`r`n", [System.Text.Encoding]::ASCII)
$zipPath = Join-Path $PSScriptRoot 'dist\SOARProbe-Windows-x64.zip'
$releaseFiles = @($exePath, (Join-Path $PSScriptRoot 'README.md'), (Join-Path $PSScriptRoot 'LICENSE.cdncheck.md'), $checksumPath)
Compress-Archive -LiteralPath $releaseFiles -DestinationPath $zipPath -Force

Build-Layout 'onedir'
$appDir = Join-Path $PSScriptRoot 'dist\SOARProbe'
foreach ($name in @('README.md', 'LICENSE.cdncheck.md', 'Start-SOARProbe.cmd')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $appDir $name) -Force
}
$portableZip = Join-Path $PSScriptRoot 'dist\SOARProbe-Windows-x64-portable.zip'
& $buildPython package_portable.py $appDir $portableZip
if ($LASTEXITCODE -ne 0) { throw 'Portable ZIP packaging or complete-file checksum verification failed.' }

# Test the delivered ZIP after extracting it to a different path, not just dist.
$portableSmoke = Join-Path ([System.IO.Path]::GetTempPath()) ('SOAR portable release smoke ' + [guid]::NewGuid().ToString('N'))
try {
    Expand-Archive -LiteralPath $portableZip -DestinationPath $portableSmoke -Force
    Test-BundledExecutable (Join-Path $portableSmoke 'SOARProbe\SOARProbe.exe') 'onedir'
    $launcherResult = @(& (Join-Path $portableSmoke 'SOARProbe\Start-SOARProbe.cmd') --self-test)
    if ($LASTEXITCODE -ne 0 -or (($launcherResult -join "`n") | ConvertFrom-Json).bundleLayout -ne 'onedir') { throw 'Portable CMD launcher did not start the extracted service correctly.' }
} finally {
    Remove-Item -LiteralPath $portableSmoke -Recurse -Force -ErrorAction SilentlyContinue
}

# This outer manifest covers every downloadable binary/archive. Each portable
# dependency also has its own entry in the ZIP's SOARProbe/SHA256SUMS.txt.
$manifest = foreach ($file in @($exePath, $zipPath, $portableZip)) {
    (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + (Split-Path -Leaf $file)
}
[System.IO.File]::WriteAllText($checksumPath, ($manifest -join "`n") + "`n", [System.Text.Encoding]::ASCII)
Write-Host ''
Write-Host 'Verified Windows x64 build:'
Write-Host $exePath
Write-Host $zipPath
Write-Host $portableZip
Write-Host ('SHA256: ' + $hash)
Write-Host 'Verified portable ZIP after extraction: PythonRuntime from its fixed _internal folder; no FastAPI/Pydantic dependency.'
Write-Host 'Application-control policy acceptance is not tested by a standard Windows runner.'
