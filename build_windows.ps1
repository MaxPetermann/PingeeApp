# Build a 64-bit, single-file Windows release for pingee.
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 'pingee requires Python 3.10 or newer to build.')"
if ($LASTEXITCODE -ne 0) { throw 'A supported Python interpreter is required.' }
$pythonBits = python -c "import struct; print(struct.calcsize('P') * 8)"
if ($LASTEXITCODE -ne 0 -or $pythonBits.Trim() -ne '64') {
    throw 'Run this script with 64-bit Python to create the x64 release.'
}

python -m pip install -r requirements-build.txt
if ($LASTEXITCODE -ne 0) { throw 'Could not install the pinned build dependencies.' }

python -m PyInstaller --noconfirm --clean --onefile --windowed `
    --name pingee --collect-all paramiko pingee.py
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller failed to build pingee.exe.' }

$zipPath = Join-Path $PSScriptRoot 'dist\pingee-windows-x64.zip'
$releaseFiles = @(
    (Join-Path $PSScriptRoot 'dist\pingee.exe'),
    (Join-Path $PSScriptRoot 'pingee.py'),
    (Join-Path $PSScriptRoot 'LICENSE'),
    (Join-Path $PSScriptRoot 'README.md'),
    (Join-Path $PSScriptRoot 'requirements-build.txt')
)
Compress-Archive -LiteralPath $releaseFiles -DestinationPath $zipPath -Force
Write-Host "Created $((Join-Path $PSScriptRoot 'dist\pingee.exe'))"
Write-Host "Created $zipPath"
