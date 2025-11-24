# TL-ICScan

> This repository contains the code and collection scripts for TL-ICScan.
>
> **TL-ICScan is developed by Tianlu Laboratory.**

[中文版](README.md) ← Chinese primary

## Introduction

TL-ICScan is a **localized vulnerability intelligence aggregation and analysis tool** developed by **Tianlu Laboratory**, designed for security researchers, Red Teams, and Blue Teams.

In daily security operations and research, we face challenges such as fragmented intelligence sources (NVD, CISA, Vendor Advisories, Exploit-DB), inconsistent data formats, and over-reliance on online queries. TL-ICScan aims to solve these problems:

- **Multi-source Aggregation**: Automatically collects and standardizes intelligence from NVD, CISA KEV, MSRC, Exploit-DB, GitHub PoC, and more.
- **Local & Private**: All data is stored in a local SQLite database, allowing offline queries and ensuring operational stealth.
- **Smart Correlation**: Automatically correlates PoC status, EPSS scores, and vendor advisories to provide a "God Mode" view.
- **Pure Intelligence**: Focuses solely on "intelligence" itself, without binding to asset management, remaining lightweight and easy to integrate.
- **Cross-Platform**: Native support for Windows, Linux, and macOS with a unified CLI experience.

---

## Key Features

1.  **Multi-source Collection (Collectors)**: Modular Python scripts supporting NVD, CISA KEV, MSRC, Exploit-DB, EPSS, GitHub PoC, etc.
2.  **Data Standardization**: Cleans heterogeneous data into a unified `NormalizedCVE` format (JSONL).
3.  **High-performance Storage**: Rust core engine handles data ingestion and indexing, supporting sub-second queries for millions of records.
4.  **Smart Digest**: Automatically generates daily/weekly vulnerability briefings in Markdown based on a YAML `watchlist`.
5.  **Flexible Export**: Supports export to JSON/CSV formats for easy import into Excel or other analysis tools.

---

## Quick Start

### 1. Prerequisites

- **Rust**: For compiling the core tool (`cargo build --release`)
- **Python 3.8+**: For running collection scripts

### 2. Installation

```bash
# 1. Build the core tool
cd tianlu-intel-core
cargo build --release
# The binary is located at target/release/tianlu-intel-core (or .exe on Windows)

# 2. Install collector dependencies
cd ../tianlu_intel_collectors
pip install -e .
```

### 3. Initialization & Update

We provide a one-click update script that automatically runs all collectors and imports data into the database (`tianlu_intel_v2.db`).

- **Windows**: Run `update_all.bat`
- **Linux/macOS**: Run `./update_all.sh`

### 4. Common Commands

All operations are performed via the CLI tool (assuming you are in the project root):

**Query Vulnerability List**
```bash
# Query high-severity vulnerabilities released in the last 7 days
./tianlu-intel-core/target/release/tianlu-intel-core list --since 7d --severity HIGH --db tianlu_intel_v2.db
```

**View Vulnerability Details**
```bash
# View detailed intelligence for a specific CVE (includes description, CVSS, PoC, references, etc.)
./tianlu-intel-core/target/release/tianlu-intel-core show CVE-2024-12345 --db tianlu_intel_v2.db
```

**Generate Intelligence Digest**
```bash
# Generate a digest based on watchlist.yml
./tianlu-intel-core/target/release/tianlu-intel-core digest --config watchlist.yml --since 1d --db tianlu_intel_v2.db
```

---

## Configuration (Watchlist)

Customize your intelligence feed by modifying `watchlist.yml`:

```yaml
- name: "Windows Core Components"
  vendors: ["microsoft"]
  products: ["windows_server_2019", "windows_10"]
  severity_min: "HIGH"

- name: "VPN Devices"
  keywords: ["vpn", "firewall", "pulse_secure"]
  epss_min: 0.1 # Only focus on vulnerabilities with > 10% exploit probability
```

---

## Contributing & Security

- For contributing code, please refer to [CONTRIBUTING_EN.md](CONTRIBUTING_EN.md)
- For reporting security issues, please refer to [SECURITY_EN.md](SECURITY_EN.md)

## License

[MIT License](LICENSE)
