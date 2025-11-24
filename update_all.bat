@echo off
chcp 65001
set PYTHONIOENCODING=utf-8
set DB_PATH=tianlu_intel_v2.db
set RUST_BIN=tianlu-intel-core\target\release\tianlu-intel-core.exe

if not exist "%RUST_BIN%" (
    echo Rust binary not found. Please run 'cargo build --release' in tianlu-intel-core directory.
    exit /b 1
)

echo Initializing database...
"%RUST_BIN%" init-db --db "%DB_PATH%"

echo Updating NVD data...
python -m tianlu_intel_collectors.nvd --since 2025-11-01 | "%RUST_BIN%" ingest --source nvd --db "%DB_PATH%"

echo Updating CISA KEV data...
python -m tianlu_intel_collectors.cisa_kev | "%RUST_BIN%" ingest --source cisa_kev --db "%DB_PATH%"

echo Updating MSRC data...
python -m tianlu_intel_collectors.msrc | "%RUST_BIN%" ingest --source msrc --db "%DB_PATH%"

echo Updating Exploit-DB data...
python -m tianlu_intel_collectors.exploit_db | "%RUST_BIN%" ingest --source exploit_db --db "%DB_PATH%"

echo Updating EPSS data...
python -m tianlu_intel_collectors.epss | "%RUST_BIN%" ingest --source epss --db "%DB_PATH%"

echo Updating GitHub PoC data...
python -m tianlu_intel_collectors.github_poc --since 7d | "%RUST_BIN%" ingest --source github_poc --db "%DB_PATH%"

echo All updates completed!
pause

