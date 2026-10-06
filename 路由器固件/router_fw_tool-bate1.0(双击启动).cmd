@echo off
rem ============================================================
rem  Launcher for router_fw_tool-bate1.0.py (double-click)
rem  ASCII-only content to avoid console encoding problems.
rem ============================================================
cd /d "%~dp0"

set "PYSCRIPT=router_fw_tool-bate1.0.py"

if not exist "%PYSCRIPT%" (
    echo [ERROR] Cannot find "%PYSCRIPT%" in:
    echo         %CD%
    echo.
    pause
    exit /b 1
)

where python >nul 2>nul
if %errorlevel%==0 (
    python "%PYSCRIPT%"
    goto :done
)

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 "%PYSCRIPT%"
    goto :done
)

echo [ERROR] Python was not found on this computer.
echo         Please install Python 3.8+ from https://www.python.org/downloads/
echo         (tick "Add python.exe to PATH" during setup), then run again.
echo.
pause
exit /b 1

:done
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Program exited with error code %errorlevel%.
    echo         Tip: run  pip install PySquashfsImage  if unpacking is unavailable.
    echo.
    pause
)
exit /b %errorlevel%
