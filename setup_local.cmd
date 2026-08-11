@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup_local.ps1"
if errorlevel 1 (
  echo.
  echo Setup failed. Please review the error message above.
  pause
  exit /b 1
)
echo.
echo Setup completed. Run start_local.cmd to start RoboGuard.
pause
