@echo off
REM NetGuard Quick Start Script

echo.
echo ==========================================
echo     NetGuard - Network Intelligence
echo ==========================================
echo.

REM Activate virtual environment
echo [1/3] Activating virtual environment...
call netguard_env\Scripts\activate.bat

REM Run migrations
echo [2/3] Syncing database...
python manage.py migrate

REM Start server
echo.
echo [3/3] Starting development server...
echo.
echo ==========================================
echo    Server running at: http://localhost:8000
echo    Login page: http://localhost:8000/login/
echo ==========================================
echo.

python manage.py runserver 8000

pause
