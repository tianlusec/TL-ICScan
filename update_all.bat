@echo off
setlocal
chcp 65001
set PYTHONIOENCODING=utf-8

:: Get the absolute path of the script directory
set "SCRIPT_DIR=%~dp0"
set "DB_PATH=%SCRIPT_DIR%tianlu_intel_v2.db"
set "RUST_BIN=%SCRIPT_DIR%tianlu-intel-core\target\release\tianlu-intel-core.exe"

:: Detect Python executable (prefer python3, then python)
where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    set "PYTHON_EXE=python"
) else (
    echo Python not found in PATH. Please install Python.
    exit /b 1
)

if not exist "%RUST_BIN%" (
    echo Rust binary not found at: %RUST_BIN%
    echo Please run 'cargo build --release' in tianlu-intel-core directory.
    exit /b 1
)

echo Initializing database...
"%RUST_BIN%" init-db --db "%DB_PATH%"
if %ERRORLEVEL% NEQ 0 goto :error

echo Updating NVD data...
"%PYTHON_EXE%" -m tianlu_intel_collectors.nvd --since 90d | "%RUST_BIN%" ingest --source nvd --db "%DB_PATH%"
if %ERRORLEVEL% NEQ 0 goto :error

echo Updating CISA KEV data...
"%PYTHON_EXE%" -m tianlu_intel_collectors.cisa_kev | "%RUST_BIN%" ingest --source cisa_kev --db "%DB_PATH%"
if %ERRORLEVEL% NEQ 0 goto :error

echo Updating MSRC data...
"%PYTHON_EXE%" -m tianlu_intel_collectors.msrc | "%RUST_BIN%" ingest --source msrc --db "%DB_PATH%"
if %ERRORLEVEL% NEQ 0 goto :error

echo Updating Exploit-DB data...
"%PYTHON_EXE%" -m tianlu_intel_collectors.exploit_db | "%RUST_BIN%" ingest --source exploit_db --db "%DB_PATH%"
if %ERRORLEVEL% NEQ 0 goto :error

echo Updating EPSS data...
"%PYTHON_EXE%" -m tianlu_intel_collectors.epss | "%RUST_BIN%" ingest --source epss --db "%DB_PATH%"
if %ERRORLEVEL% NEQ 0 goto :error

echo Updating GitHub PoC data...
"%PYTHON_EXE%" -m tianlu_intel_collectors.github_poc --since 7d | "%RUST_BIN%" ingest --source github_poc --db "%DB_PATH%"
if %ERRORLEVEL% NEQ 0 goto :error

echo All updates completed successfully!
pause
exit /b 0

:error
echo An error occurred during the update process.
pause
exit /b 1

