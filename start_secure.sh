#!/bin/bash

echo "========================================"
echo "Aircraft Maintenance System (SECURE)"
echo "========================================"
echo

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    echo "Please install Python 3.7+ first"
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "ERROR: pip3 is not installed"
    echo "Please install pip3 first"
    exit 1
fi

# Check if required packages are installed
echo "Checking security dependencies..."
python3 -c "import flask_limiter, flask_wtf, cryptography" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Installing security dependencies..."
    pip3 install -r requirements_secure.txt
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install dependencies"
        exit 1
    fi
fi

echo
echo "Starting SECURE Aircraft Maintenance System..."
echo
echo "Security Features:"
echo "- Enhanced password hashing"
echo "- Account lockout protection"
echo "- Rate limiting"
echo "- CSRF protection"
echo "- Security headers"
echo "- Audit logging"
echo "- Input validation"
echo "- Session security"
echo "- Data encryption"
echo
echo "Default accounts (NIK/Password):"
echo "- Admin: 001/123"
echo "- Mechanic: 002/123"
echo "- Quality Inspector: 003/123"
echo "- Quality CUDR: 004/123"
echo "- Super Admin: 005/123"
echo
echo "WARNING: Account locks after 5 failed attempts!"
echo

python3 run_secure.py

if [ $? -ne 0 ]; then
    echo
    echo "ERROR: Application failed to start"
    echo "Check the error messages above"
    read -p "Press Enter to continue..."
fi