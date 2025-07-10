@echo off
echo ========================================
echo Aircraft Maintenance System (SECURE)
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7+ from https://python.org
    pause
    exit /b 1
)

REM Check if required packages are installed
echo Checking security dependencies...
python -c "import flask_limiter, flask_wtf, cryptography" >nul 2>&1
if errorlevel 1 (
    echo Installing security dependencies...
    pip install -r requirements_secure.txt
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
)

echo.
echo Starting SECURE Aircraft Maintenance System...
echo.
echo Security Features:
echo - Enhanced password hashing
echo - Account lockout protection  
echo - Rate limiting
echo - CSRF protection
echo - Security headers
echo - Audit logging
echo - Input validation
echo - Session security
echo - Data encryption
echo.
echo Default accounts (NIK/Password):
echo - Admin: 001/123
echo - Mechanic: 002/123  
echo - Quality Inspector: 003/123
echo - Quality CUDR: 004/123
echo - Super Admin: 005/123
echo.
echo WARNING: Account locks after 5 failed attempts!
echo.

python run_secure.py

if errorlevel 1 (
    echo.
    echo ERROR: Application failed to start
    echo Check the error messages above
    pause
)