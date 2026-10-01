@echo off
REM One-time setup: verify Python, then the first run needs nothing else.
cd /d "%~dp0"
setlocal
chcp 65001 >nul 2>&1

set "PYEXE="
where py >nul 2>&1 && set "PYEXE=py -3.13"
if not defined PYEXE ( where python >nul 2>&1 && set "PYEXE=python" )
if not defined PYEXE (
  echo.
  echo   Python 3.11+ is required and was not found.
  echo   Download it from https://www.python.org/downloads/
  echo   Be sure to tick "Add python.exe to PATH" during setup.
  echo.
  pause
  exit /b 1
)

set "PYTHONUTF8=1"
set "PYTHONPATH=%CD%"

echo.
echo   Running CyberKit self-check...
echo.
%PYEXE% -m cyberkit.cli modules
echo.
if errorlevel 1 (
  echo   Self-check failed. The error above explains why.
  pause
  exit /b 1
)
echo   Ready. Launch the interface with CYBERKIT.bat
echo.
pause
endlocal