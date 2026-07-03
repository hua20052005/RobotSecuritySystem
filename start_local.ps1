$ErrorActionPreference = "Stop"

$Root = $PSScriptRoot
$WebRoot = Join-Path $Root "web"
$LogRoot = Join-Path $Root ".runlogs"
New-Item -ItemType Directory -Force -Path $LogRoot | Out-Null

function Test-PythonRuntime {
    param([string]$Executable)
    if (-not (Test-Path -LiteralPath $Executable)) {
        return $false
    }
    & $Executable -c "import fastapi, uvicorn, numpy, sklearn, scapy" 2>$null
    return $LASTEXITCODE -eq 0
}

$pythonCandidates = @(
    $env:ROBOGUARD_PYTHON,
    (Join-Path $Root ".venv\Scripts\python.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\Python\Python311\python.exe")
) | Where-Object { $_ }

$Python = $null
foreach ($candidate in $pythonCandidates) {
    if (Test-PythonRuntime $candidate) {
        $Python = $candidate
        break
    }
}

if (-not $Python) {
    throw "No compatible Python runtime found. Install dependencies or set ROBOGUARD_PYTHON."
}

if (-not (Test-Path -LiteralPath (Join-Path $WebRoot "node_modules"))) {
    throw "web\node_modules is missing. Run npm ci in the web directory first."
}

$BackendPort = 8010
if (Get-NetTCPConnection -LocalPort $BackendPort -State Listen -ErrorAction SilentlyContinue) {
    $BackendPort = 8011
}

$backendOut = Join-Path $LogRoot "backend.out.log"
$backendErr = Join-Path $LogRoot "backend.err.log"
$backend = Start-Process `
    -FilePath $Python `
    -ArgumentList @(
        "-m", "uvicorn", "backend.payload_api.main:app",
        "--host", "127.0.0.1",
        "--port", "$BackendPort"
    ) `
    -WorkingDirectory $Root `
    -WindowStyle Hidden `
    -RedirectStandardOutput $backendOut `
    -RedirectStandardError $backendErr `
    -PassThru
Set-Content -LiteralPath (Join-Path $LogRoot "backend.pid") -Value $backend.Id
Set-Content -LiteralPath (Join-Path $LogRoot "backend.port") -Value $BackendPort

$healthUrl = "http://127.0.0.1:$BackendPort/health"
$backendReady = $false
for ($i = 0; $i -lt 30; $i++) {
    try {
        $null = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2
        $backendReady = $true
        break
    } catch {
        Start-Sleep -Milliseconds 500
    }
}

if (-not $backendReady) {
    throw "Backend failed to start. See $backendErr"
}

$env:VITE_API_BASE_URL = "http://127.0.0.1:$BackendPort"
$frontendOut = Join-Path $LogRoot "frontend.out.log"
$frontendErr = Join-Path $LogRoot "frontend.err.log"
$frontend = Start-Process `
    -FilePath "npm.cmd" `
    -ArgumentList @("run", "dev", "--", "--host", "127.0.0.1", "--port", "5173") `
    -WorkingDirectory $WebRoot `
    -WindowStyle Hidden `
    -RedirectStandardOutput $frontendOut `
    -RedirectStandardError $frontendErr `
    -PassThru
Set-Content -LiteralPath (Join-Path $LogRoot "frontend.pid") -Value $frontend.Id
Set-Content -LiteralPath (Join-Path $LogRoot "frontend.port") -Value 5173

$frontendReady = $false
for ($i = 0; $i -lt 30; $i++) {
    try {
        $response = Invoke-WebRequest -Uri "http://127.0.0.1:5173/" -UseBasicParsing -TimeoutSec 2
        if ($response.StatusCode -eq 200) {
            $frontendReady = $true
            break
        }
    } catch {
        Start-Sleep -Milliseconds 500
    }
}

if (-not $frontendReady) {
    throw "Frontend failed to start. See $frontendErr"
}

Write-Host ""
Write-Host "RoboGuard started." -ForegroundColor Green
Write-Host "Frontend: http://127.0.0.1:5173/"
Write-Host "Backend:  http://127.0.0.1:$BackendPort/"
Write-Host "Stop:     .\stop_local.cmd"
