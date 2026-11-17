$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Find-Python {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        try {
            & py -3 -c "import sys; assert sys.version_info >= (3,11) and sys.maxsize > 2**32" 2>$null
            if ($LASTEXITCODE -eq 0) { return [pscustomobject]@{ Program = 'py'; Arguments = @('-3') } }
        } catch { }
    }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        try {
            & python -c "import sys; assert sys.version_info >= (3,11) and sys.maxsize > 2**32" 2>$null
            if ($LASTEXITCODE -eq 0) { return [pscustomobject]@{ Program = 'python'; Arguments = @() } }
        } catch { }
    }
    throw 'Install 64-bit Python 3.11 or newer from https://www.python.org/downloads/windows/ (include the Python launcher).'
}

$pythonCommand = Find-Python
$program = [string]$pythonCommand.Program
$pythonArguments = @($pythonCommand.Arguments)
if (-not (Test-Path -LiteralPath '.venv\Scripts\python.exe')) {
    & $program @pythonArguments -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Creating the virtual environment failed.' }
}
& '.\.venv\Scripts\python.exe' -c "import sys; assert sys.version_info >= (3,11) and sys.maxsize > 2**32, 'The virtual environment requires 64-bit Python 3.11 or newer'"
if ($LASTEXITCODE -ne 0) { throw 'The existing .venv is incompatible. Rename it, then run Install.cmd again with 64-bit Python 3.11 or newer installed.' }
& '.\.venv\Scripts\python.exe' -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed. Check access to your Python package index.' }
& '.\.venv\Scripts\python.exe' service.py --init-config
if ($LASTEXITCODE -ne 0) { throw 'Creating or validating config.json failed.' }
Write-Host ''
Write-Host 'Installed. Run Start.cmd, then Show-Token.cmd to copy the pairing token into the userscript settings.'
Write-Host 'No administrator privileges or Windows Telnet client are required.'
