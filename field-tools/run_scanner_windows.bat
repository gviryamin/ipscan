@echo off
setlocal
title Site Network Scanner
cd /d "%~dp0\.."

echo Starting Site Network Scanner...
echo.
echo The scanner runs locally on this laptop.
echo Browser address: http://127.0.0.1:8765
echo.
echo Multi-range examples:
echo 192.168.1.0/24
echo 192.168.1.10-192.168.1.50
echo 172.19.1.0-172.19.65.0/24
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

python field-tools\site_network_scanner_multi_range.py
pause
