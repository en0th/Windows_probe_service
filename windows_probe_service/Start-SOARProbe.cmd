@echo off
setlocal
cd /d "%~dp0"
set "SOAR_PROBE_CMD_LAUNCH=1"
"%~dp0SOARProbe.exe" %*
set "SOAR_PROBE_EXIT_CODE=%ERRORLEVEL%"
if "%SOAR_PROBE_EXIT_CODE%"=="0" exit /b 0
echo.
echo SOARProbe failed to start. Keep the error above for support.
echo Extract the complete ZIP and keep its _internal directory with the EXE.
echo This launcher does not change Windows application control policies.
if not "%~1"=="" exit /b %SOAR_PROBE_EXIT_CODE%
if defined CI exit /b %SOAR_PROBE_EXIT_CODE%
pause
exit /b %SOAR_PROBE_EXIT_CODE%
