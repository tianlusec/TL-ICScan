#!/usr/bin/env bash
set -e

DB_PATH="tianlu_intel_v2.db"
RUST_BIN="./tianlu-intel-core/target/release/tianlu-intel-core"

if [ ! -f "$RUST_BIN" ]; then
    echo "Rust binary not found. Please run 'cargo build --release' in tianlu-intel-core directory."
    exit 1
fi

# 1. Init DB
"$RUST_BIN" init-db --db "$DB_PATH"

# 2. Update NVD
echo "Updating NVD..."
python -m tianlu_intel_collectors.nvd --since 90d \
  | "$RUST_BIN" ingest --source nvd --db "$DB_PATH"

# 3. Update CISA KEV
echo "Updating CISA KEV..."
python -m tianlu_intel_collectors.cisa_kev \
  | "$RUST_BIN" ingest --source cisa_kev --db "$DB_PATH"

# 4. Update MSRC
echo "Updating MSRC..."
python -m tianlu_intel_collectors.msrc \
  | "$RUST_BIN" ingest --source msrc --db "$DB_PATH"

# 5. Update Exploit-DB
echo "Updating Exploit-DB..."
python -m tianlu_intel_collectors.exploit_db \
  | "$RUST_BIN" ingest --source exploit_db --db "$DB_PATH"

# 6. Update EPSS
echo "Updating EPSS..."
python -m tianlu_intel_collectors.epss \
  | "$RUST_BIN" ingest --source epss --db "$DB_PATH"

# 7. Update GitHub PoC
echo "Updating GitHub PoC..."
python -m tianlu_intel_collectors.github_poc --since 7d \
  | "$RUST_BIN" ingest --source github_poc --db "$DB_PATH"

echo "All updates completed."
