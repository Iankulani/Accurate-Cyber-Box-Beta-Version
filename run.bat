@echo off
REM CyberDrill Startup Script for Windows

echo ================================
echo CyberDrill Security Tool
echo ================================

REM Check Python version
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    exit /b 1
)

echo Python version:
python --version

REM Create virtual environment if it doesn't exist
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install requirements
echo Installing requirements...
pip install -r requirements.txt

REM Create necessary directories
if not exist "data" mkdir data
if not exist "icons" mkdir icons

REM Run the application
echo Starting CyberDrill...
python cyberdrill.py %*

REM Deactivate virtual environment
call deactivate