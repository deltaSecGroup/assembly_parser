@echo off
echo Building project into a standalone executable...

pip install pyinstaller

pyinstaller --onefile --windowed assembly_parser.py

echo Build complete! The executable is located in the 'dist' folder.
pause
