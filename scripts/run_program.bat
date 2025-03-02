@echo off
echo Checking if dependencies are installed...
pip show capstone >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo capstone is not installed. Installing dependencies...
    call scripts\install_requirements.bat
)

echo Running assembly_parser.py...
python assembly_parser.py
pause
