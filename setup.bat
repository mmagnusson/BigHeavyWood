@echo off
echo ====================================
echo Forensic Log Analyzer - Setup
echo ====================================
echo.

echo Checking Python installation...
python --version
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from python.org
    pause
    exit /b 1
)
echo.

echo Creating virtual environment...
python -m venv venv
if errorlevel 1 (
    echo ERROR: Failed to create virtual environment
    pause
    exit /b 1
)
echo.

echo Activating virtual environment...
call venv\Scripts\activate.bat
echo.

echo Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)
echo.

echo Creating necessary directories...
if not exist "uploads" mkdir uploads
if not exist "exports" mkdir exports
echo.

echo ====================================
echo Setup Complete!
echo ====================================
echo.
echo To start the application, run:
echo   start.bat
echo.
pause
