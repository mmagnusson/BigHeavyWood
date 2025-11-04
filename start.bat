@echo off
echo ====================================
echo Forensic Log Analyzer
echo ====================================
echo.

echo Activating virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo ERROR: Virtual environment not found
    echo Please run setup.bat first
    pause
    exit /b 1
)
echo.

echo Starting Flask application...
echo.
echo Application will be available at:
echo http://localhost:5000
echo.
echo Press CTRL+C to stop the server
echo.

python app.py
