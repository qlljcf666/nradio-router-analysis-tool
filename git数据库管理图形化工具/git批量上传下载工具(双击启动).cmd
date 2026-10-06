@echo off
setlocal
cd /d "%~dp0"

rem ============================================================
rem  Git Batch Upload/Download Tool - Launcher
rem  1. Prefer the packaged exe (no Python required)
rem  2. Fall back to pythonw (no console window)
rem  3. Fall back to python
rem  4. Check git availability
rem ============================================================

if exist "%~dp0git批量上传下载工具.exe" (
    start "" "%~dp0git批量上传下载工具.exe"
    goto :eof
)

if exist "%~dp0git批量上传下载工具.py" (
    where pythonw >nul 2>nul
    if %errorlevel%==0 (
        start "" pythonw "%~dp0git批量上传下载工具.py"
        goto :eof
    )

    where python >nul 2>nul
    if %errorlevel%==0 (
        start "" python "%~dp0git批量上传下载工具.py"
        goto :eof
    )

    echo [ERROR] Python not found in PATH.
    echo Please install Python 3.8+ or use the packaged .exe.
    echo.
    pause
    goto :eof
)

echo [ERROR] Program file not found:
echo   git批量上传下载工具.exe
echo   git批量上传下载工具.py
echo.
pause
endlocal
