@echo off
echo Cleaning up build files...

rd /s /q build
rd /s /q dist
del /q assembly_parser.spec

echo Cleanup complete!
pause
