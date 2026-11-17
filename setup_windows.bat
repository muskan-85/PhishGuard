@echo off
title PhishGuard setup
cd /d "%~dp0"
echo Creating virtual environment (.venv)...
python -m venv .venv || goto :error
echo Installing dependencies...
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt || goto :error
echo.
echo Setup complete. Start the app with run.bat
pause
exit /b 0
:error
echo Setup failed. Check that Python 3.11 or newer is installed and on PATH.
pause
exit /b 1
