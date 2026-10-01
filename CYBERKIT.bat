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
REM Order matters: chcp changes the console code page for the child, but
REM Python reads it through the C runtime, so PYTHONIOENCODING has to be set
REM explicitly. Without it sys.stdout.encoding stays cp1254 on a Turkish
REM Windows and every box-drawing glyph is transliterated to "?".
chcp 65001 >nul 2>&1
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8:replace"
set "PYTHONPATH=%CD%"
%PYEXE% -c "import sys;sys.stdout.reconfigure(encoding='utf-8',errors='replace')" >nul 2>&1

%PYEXE% -m cyberkit.app
if errorlevel 1 pause
endlocal
