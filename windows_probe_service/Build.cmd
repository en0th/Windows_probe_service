@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Build.ps1"
if errorlevel 1 (
  echo Build failed. No verified EXE package was produced.
  pause
  exit /b 1
)
echo Build complete. See the dist folder.
pause
