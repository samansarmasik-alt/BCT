@echo off
REM CyberKit interactive shell. Double-click to launch.
cd /d "%~dp0"
setlocal

set "PYEXE="
where py >nul 2>&1 && set "PYEXE=py -3.13"
if not defined PYEXE ( where python >nul 2>&1 && set "PYEXE=python" )
if not defined PYEXE (
  echo Python not found. Install Python 3.11 or newer, then run this again.
  pause
  exit /b 1
)

REM UTF-8 console so Turkish characters and box drawing render correctly.
chcp 65001 >nul 2>&1
set "PYTHONUTF8=1"
set "PYTHONPATH=%CD%"

%PYEXE% -m cyberkit.app
if errorlevel 1 pause
endlocal
