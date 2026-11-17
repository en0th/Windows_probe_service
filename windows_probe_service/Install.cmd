@echo off
setlocal
cd /d "%~dp0"
if exist "SOARProbe.exe" (
  echo Standalone EXE found. No Python installation is needed. Run SOARProbe.exe.
  pause
  exit /b 0
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install.ps1"
if errorlevel 1 (
  echo Installation failed.
  pause
  exit /b 1
)
pause
