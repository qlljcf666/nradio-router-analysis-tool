@echo off
chcp 65001 >nul
cd /d "%~dp0"
python "%~dp0nr_tool.py" menu
if errorlevel 1 py "%~dp0nr_tool.py" menu
pause
