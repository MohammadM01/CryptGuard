@echo off
echo ===================================================
echo Starting CryptGuard Project
echo ===================================================
echo.

echo [1/3] Starting Frontend (React)...
start "CryptGuard Frontend" cmd /k "cd frontend && npm install && npm run dev"

echo [2/3] Starting Backend (FastAPI)...
start "CryptGuard Backend" cmd /k "cd backend && if not exist venv (python -m venv venv) && call venv\Scripts\activate && pip install -r requirements.txt && python main.py"

echo [3/3] Starting Packet Analyzer (C++ Engine)...
start "CryptGuard DPI Engine" cmd /k "cd Packet_analyzer && echo Generating test traffic... && python generate_test_pcap.py && echo Running Engine... && dpi_engine.exe test_dpi.pcap output.pcap"

echo.
echo All components are starting up in separate windows!
echo - Frontend: http://localhost:5173
echo - Backend: http://localhost:8000
echo.
echo You can double-click this script (start_project.bat) anytime to turn on the project.
pause
