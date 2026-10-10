@echo off
powershell.exe -NoProfile -File "%~dp0Start-Sentinel.ps1"
if errorlevel 1 (
    echo Sentinel could not start. Read the setup message above.
    pause
)
