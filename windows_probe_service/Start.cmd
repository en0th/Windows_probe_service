@echo off
setlocal
cd /d "%~dp0"
if exist "SOARProbe.exe" (
  "SOARProbe.exe"
  exit /b
)
if not exist ".venv\Scripts\python.exe" (
  echo Run Install.cmd first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" service.py
if errorlevel 1 (
  echo Service stopped with an error. Check the message above and the configuration.
  pause
  exit /b 1
)
