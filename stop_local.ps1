$ErrorActionPreference = "SilentlyContinue"

$LogRoot = Join-Path $PSScriptRoot ".runlogs"
foreach ($name in @("frontend", "backend")) {
    $pidFile = Join-Path $LogRoot "$name.pid"
    if (-not (Test-Path -LiteralPath $pidFile)) {
        continue
    }

    $processId = [int](Get-Content -LiteralPath $pidFile -Raw)
    if (Get-Process -Id $processId -ErrorAction SilentlyContinue) {
        & taskkill.exe /PID $processId /T /F | Out-Null
        Write-Host "$name stopped (PID $processId)"
    }
    Remove-Item -LiteralPath $pidFile -Force

    $portFile = Join-Path $LogRoot "$name.port"
    if (Test-Path -LiteralPath $portFile) {
        $port = [int](Get-Content -LiteralPath $portFile -Raw)
        $listeners = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
        foreach ($listener in $listeners) {
            $listenerPid = [int]$listener.OwningProcess
            if (Get-Process -Id $listenerPid -ErrorAction SilentlyContinue) {
                Stop-Process -Id $listenerPid -Force
                Write-Host "$name listener stopped (PID $listenerPid, port $port)"
            }
        }
        Remove-Item -LiteralPath $portFile -Force
    }
}

Write-Host "RoboGuard local services stopped."
