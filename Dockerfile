# Stage 1: Build Rust Core
FROM rust:1.85-slim-bookworm as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev libsqlite3-dev

# Copy Rust source code
COPY tianlu-intel-core ./tianlu-intel-core

# Build release binary
WORKDIR /build/tianlu-intel-core
RUN cargo build --release

# Stage 2: Python Runtime
FROM python:3.11-slim-bookworm

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libsqlite3-0 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
COPY tianlu_intel_collectors ./tianlu_intel_collectors
RUN pip install --no-cache-dir -r requirements.txt

# Copy Rust binary from builder
COPY --from=builder /build/tianlu-intel-core/target/release/tianlu-intel-core /usr/local/bin/tianlu-intel-core

# Copy application code
COPY web_ui ./web_ui
COPY watchlist.yml .

# Create a script for updating data
RUN echo '#!/bin/bash\n\
    set -e\n\
    DB_PATH=${TIANLU_DB_PATH:-/data/tianlu_intel_v2.db}\n\
    echo "Initializing DB at $DB_PATH..."\n\
    tianlu-intel-core init-db --db "$DB_PATH"\n\
    \n\
    echo "Updating NVD..."\n\
    python -m tianlu_intel_collectors.nvd --since 7d | tianlu-intel-core ingest --source nvd --db "$DB_PATH"\n\
    \n\
    echo "Updating CISA KEV..."\n\
    python -m tianlu_intel_collectors.cisa_kev | tianlu-intel-core ingest --source cisa_kev --db "$DB_PATH"\n\
    \n\
    echo "Updating MSRC..."\n\
    python -m tianlu_intel_collectors.msrc | tianlu-intel-core ingest --source msrc --db "$DB_PATH"\n\
    \n\
    echo "Updating Exploit-DB..."\n\
    python -m tianlu_intel_collectors.exploit_db | tianlu-intel-core ingest --source exploit_db --db "$DB_PATH"\n\
    \n\
    echo "Updating EPSS..."\n\
    python -m tianlu_intel_collectors.epss | tianlu-intel-core ingest --source epss --db "$DB_PATH"\n\
    \n\
    echo "Updating GitHub PoC..."\n\
    python -m tianlu_intel_collectors.github_poc --since 7d | tianlu-intel-core ingest --source github_poc --db "$DB_PATH"\n\
    \n\
    echo "Update completed!"\n\
    ' > /usr/local/bin/update-data && chmod +x /usr/local/bin/update-data

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV TIANLU_DB_PATH=/data/tianlu_intel_v2.db

# Create volume mount point
VOLUME /data

# Expose Web UI port
EXPOSE 8501

# Healthcheck
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Default command: Run Web UI
CMD ["streamlit", "run", "web_ui/dashboard.py", "--server.address=0.0.0.0"]
