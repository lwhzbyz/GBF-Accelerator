@echo off
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" app_main.py --gui %*
) else (
  py -3.12 app_main.py --gui %*
)
if errorlevel 1 pause
