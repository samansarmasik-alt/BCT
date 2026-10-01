@echo off
REM Run the CyberKit test suite.
cd /d "%~dp0"
set "PYTHONPATH=%CD%"
py -3.13 -m unittest discover -s tests -t . %*
if errorlevel 1 pause
