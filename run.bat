@echo off
title PhishGuard
cd /d "%~dp0"
echo.
echo ========================================
echo        PhishGuard - Phishing Detection
echo ========================================
echo.
if exist ".venv\Scripts\python.exe" (set "PY=.venv\Scripts\python.exe") else (set "PY=python")

if not exist "model\phishing_model.pkl" (
    echo Model file not found - training it now...
    %PY% model\train_model.py
    echo.
)
echo Open http://127.0.0.1:5000 in your browser. Press Ctrl+C to stop.
echo.
%PY% app.py
pause
