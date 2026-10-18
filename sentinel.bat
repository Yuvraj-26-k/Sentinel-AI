@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sentinel.ps1"
endlocal
