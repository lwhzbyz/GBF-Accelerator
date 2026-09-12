@echo off
cd /d "%~dp0"
echo This explicitly installs the current local CA in CurrentUser Root.
echo For an old CA migration, read README.md before using --remove-legacy-ca.
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" app_main.py --install-ca %*
) else (
  py -3.12 app_main.py --install-ca %*
)
if errorlevel 1 (
  echo CA installation did not complete. See the message above.
  pause
  exit /b 1
)
echo Current CA installation verified.
pause
