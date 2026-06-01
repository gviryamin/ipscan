@echo off
setlocal
title Site Network Scanner
cd /d "%~dp0\.."

echo Starting Site Network Scanner...
echo.
echo The scanner runs locally on this laptop.
echo Browser address: http://127.0.0.1:8765
echo.
echo Use only on networks you are authorized to scan.
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo Python was not found.
    echo Install Python 3 from https://www.python.org/downloads/ before going to the field.
    echo Make sure to check "Add python.exe to PATH" during installation.
    pause
    exit /b 1
)

python field-tools\site_network_scanner.py
pause
