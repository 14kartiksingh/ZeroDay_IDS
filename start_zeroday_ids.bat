@echo off
title ZeroDay IDS — Master Demo Launcher
color 0B

echo ============================================================
echo        ZeroDay IDS - Starting Complete Demo Environment
echo ============================================================
echo.

cd /d "%~dp0"

echo [1/3] Starting Protected Target Website (NexaVault on Port 8001)...
start "1. Protected Website (Port 8001)" cmd /k "cd /d "%~dp0website" && ..\venv\Scripts\python.exe -m http.server 8001 --bind 0.0.0.0"

timeout /t 2 /nobreak >nul

echo [2/3] Starting 6-Component ML Detection Backend (FastAPI on Port 8000)...
start "2. ML Detection Backend (Port 8000)" cmd /k "cd /d "%~dp0" && venv\Scripts\uvicorn.exe backend.api.main:app --host 0.0.0.0 --port 8000"

timeout /t 4 /nobreak >nul

echo [3/3] Starting React Live Threat Monitor (Port 5173)...
start "3. React Detection Dashboard (Port 5173)" cmd /k "cd /d "%~dp0frontend" && npm run dev"

timeout /t 3 /nobreak >nul

echo.
echo Opening Live Threat Monitor in your browser...
start http://localhost:5173

echo.
echo ============================================================
echo   All 3 services are running!
echo   - Protected Website : http://localhost:8001
echo   - ML Backend API    : http://localhost:8000
echo   - Threat Dashboard  : http://localhost:5173
echo ============================================================
pause
