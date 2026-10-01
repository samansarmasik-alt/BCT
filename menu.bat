@echo off
REM Double-click launcher for CyberKit. Keeps the window open so output stays readable.
cd /d "%~dp0"
set "PYEXE="
where py >nul 2>&1 && set "PYEXE=py -3.13"
if not defined PYEXE ( where python >nul 2>&1 && set "PYEXE=python" )
if not defined PYEXE (
  echo Python not found. Install Python 3.11+ and retry.
  pause
  exit /b 1
)
set "PYTHONPATH=%CD%"
%PYEXE% -m cyberkit.menu
if errorlevel 1 pause
