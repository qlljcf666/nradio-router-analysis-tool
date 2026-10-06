@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
if "%~1"=="" (
  echo ============================================================
  echo  Drag your device backup .nr file onto this icon,
  echo  or run:  nr_onekey.cmd  path\to\backup.nr
  echo ============================================================
  pause
  exit /b 1
)
python "%~dp0nr_tool.py" unlock "%~1"
if errorlevel 1 (
  echo.
  echo [python] not found, trying [py] launcher ...
  py "%~dp0nr_tool.py" unlock "%~1"
)
echo.
pause
