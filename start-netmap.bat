@echo off
REM NetMap one-click starter (Windows): backend :8000 + frontend :5173, browser opens automatically.
REM First time only: pip install -r backend\requirements.txt  ^&  npm install --prefix frontend
cd /d "%~dp0backend"
start "NetMap backend :8000" cmd /k "python -m uvicorn app:app --host 127.0.0.1 --port 8000"
cd /d "%~dp0frontend"
timeout /t 4 /nobreak >nul
start "NetMap frontend :5173" cmd /k "npm run dev"
echo NetMap starting: backend http://127.0.0.1:8000/api/health, UI opens at http://127.0.0.1:5173
