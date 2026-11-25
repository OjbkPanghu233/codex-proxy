@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-windows.ps1" %*
set "CODEX_PROXY_SETUP_EXIT=%errorlevel%"
if "%~1"=="" pause
exit /b %CODEX_PROXY_SETUP_EXIT%
