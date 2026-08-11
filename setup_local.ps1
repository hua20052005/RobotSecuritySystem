$ErrorActionPreference = "Stop"

$Root = $PSScriptRoot
$WebRoot = Join-Path $Root "web"
$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"

Write-Host "RoboGuard first-time setup" -ForegroundColor Cyan
Write-Host "Project: $Root"

if (-not (Test-Path -LiteralPath $VenvPython)) {
    Write-Host ""
    Write-Host "[1/3] Creating Python virtual environment..."

    $pyLauncher = Get-Command "py.exe" -ErrorAction SilentlyContinue
    $python = Get-Command "python.exe" -ErrorAction SilentlyContinue

    if ($pyLauncher) {
        & $pyLauncher.Source -3.11 -c "import sys; assert sys.version_info[:2] == (3, 11)"
        if ($LASTEXITCODE -ne 0) {
            throw "Python 3.11 was not found. Install Python 3.11 (64-bit) and retry."
        }
        & $pyLauncher.Source -3.11 -m venv (Join-Path $Root ".venv")
    } elseif ($python) {
        & $python.Source -c "import sys; assert (3, 10) <= sys.version_info[:2] <= (3, 12)"
        if ($LASTEXITCODE -ne 0) {
            throw "Python 3.10-3.12 was not found. Python 3.11 (64-bit) is recommended."
        }
        & $python.Source -m venv (Join-Path $Root ".venv")
    } else {
        throw "Python was not found. Install Python 3.11 (64-bit), then retry."
    }
} else {
    Write-Host ""
    Write-Host "[1/3] Existing Python virtual environment found."
}

Write-Host ""
Write-Host "[2/3] Installing Python dependencies..."
& $VenvPython -m pip install --upgrade pip
& $VenvPython -m pip install -r (Join-Path $Root "requirements.txt")

$npm = Get-Command "npm.cmd" -ErrorAction SilentlyContinue
if (-not $npm) {
    throw "npm was not found. Install Node.js 20 or newer, then retry."
}

Write-Host ""
Write-Host "[3/3] Installing frontend dependencies..."
Push-Location $WebRoot
try {
    & $npm.Source ci
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "Verifying installation..."
& $VenvPython -c "import fastapi, uvicorn, numpy, sklearn, scapy, paramiko; print('Python runtime: OK')"
Push-Location $WebRoot
try {
    & $npm.Source run build
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "Setup completed successfully." -ForegroundColor Green
Write-Host "Next step: run .\start_local.cmd"
