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
& $buildPython -m pip install --disable-pip-version-check -r requirements-build.txt
if ($LASTEXITCODE -ne 0) { throw 'Installing build dependencies failed. Check access to the configured Python package index.' }
& $buildPython -m pip check
if ($LASTEXITCODE -ne 0) { throw 'Build dependencies are inconsistent.' }
& $buildPython -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { throw 'Offline service tests failed; EXE generation stopped.' }

& $buildPython -m PyInstaller --noconfirm --clean --distpath dist --workpath .build-cache SOARProbe.spec
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller failed.' }
$exePath = Join-Path $PSScriptRoot 'dist\SOARProbe.exe'
if (-not (Test-Path -LiteralPath $exePath)) { throw 'The expected SOARProbe.exe was not created.' }

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
if ($selfTest.status -ne 'ok' -or $selfTest.frozen -ne $true) { throw 'The EXE did not confirm bundled runtime/resources in its self-test.' }

# Smoke the actual bundled ASGI server on loopback, without submitting targets.
$smokeDir = Join-Path ([System.IO.Path]::GetTempPath()) ('soar-exe-smoke-' + [guid]::NewGuid().ToString('N'))
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
    $process = Start-Process -FilePath $exePath -ArgumentList $arguments -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $smokeDir 'stdout.log') -RedirectStandardError (Join-Path $smokeDir 'stderr.log')
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
    $auth = Invoke-RestMethod -Uri ($smokeUrl + '/v1/auth-check') -Headers @{ Authorization = 'Bearer ' + $smokeConfig.token } -TimeoutSec 3
    if ($auth.status -ne 'ok' -or $auth.apiVersion -ne 1) { throw 'The bundled service failed its authenticated check.' }
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

$hash = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256).Hash.ToLowerInvariant()
$checksumPath = Join-Path $PSScriptRoot 'dist\SHA256SUMS.txt'
[System.IO.File]::WriteAllText($checksumPath, $hash + '  SOARProbe.exe' + "`r`n", [System.Text.Encoding]::ASCII)
$zipPath = Join-Path $PSScriptRoot 'dist\SOARProbe-Windows-x64.zip'
$releaseFiles = @($exePath, (Join-Path $PSScriptRoot 'README.md'), (Join-Path $PSScriptRoot 'LICENSE.cdncheck.md'), $checksumPath)
Compress-Archive -LiteralPath $releaseFiles -DestinationPath $zipPath -Force
Write-Host ''
Write-Host 'Verified Windows x64 build:'
Write-Host $exePath
Write-Host $zipPath
Write-Host ('SHA256: ' + $hash)
Write-Host 'Distribute the EXE or release ZIP. End users do not need Python or dependency installation.'
