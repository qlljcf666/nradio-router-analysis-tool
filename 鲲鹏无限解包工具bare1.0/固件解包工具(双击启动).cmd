@echo off
rem Pure-ASCII launcher: locates the GUI script by an internal marker,
rem so non-ASCII file/directory names never appear in this batch file.
cd /d "%~dp0"
set "GUIPY="
for /f "delims=" %%F in ('dir /b *.py 2^>nul') do (
  findstr /c:"firmware-unpack" "%%F" >nul 2>&1 && set "GUIPY=%%F"
)
if "%GUIPY%"=="" (
  echo GUI script not found in this folder.
  pause
  exit /b 1
)
python "%GUIPY%"
if errorlevel 1 (
  echo.
  echo [python] not found, trying [py] launcher ...
  py "%GUIPY%"
)
pause
