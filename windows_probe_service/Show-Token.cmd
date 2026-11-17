@echo off
setlocal
cd /d "%~dp0"
if exist "SOARProbe.exe" (
  "SOARProbe.exe" --copy-token
  if errorlevel 1 "SOARProbe.exe" --show-token
  pause
  exit /b
)
if not exist ".venv\Scripts\python.exe" (
  echo Run Install.cmd first.
  pause
  exit /b 1
)
echo Pairing token - copy into the userscript settings. Do not share it in diagnostic logs.
".venv\Scripts\python.exe" service.py --show-token
pause
