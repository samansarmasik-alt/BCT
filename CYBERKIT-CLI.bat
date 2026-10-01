@echo off
REM CyberKit - non-interactive command line.
REM Usage: CYBERKIT-CLI.bat https://site.com
cd /d "%~dp0"
setlocal
set "PYEXE="
where py >nul 2>&1 && set "PYEXE=py -3.13"
if not defined PYEXE ( where python >nul 2>&1 && set "PYEXE=python" )
chcp 65001 >nul 2>&1
set "PYTHONUTF8=1"
set "PYTHONPATH=%CD%"
%PYEXE% -m cyberkit.cli %*
endlocal
