# TL-ICScan Vulnerability Intelligence Aggregation and Analysis Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Rust 1.70+](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![GitHub release](https://img.shields.io/github/v/release/tianlusec/TL-ICScan)](https://github.com/tianlusec/TL-ICScan/releases)
[![GitHub stars](https://img.shields.io/github/stars/tianlusec/TL-ICScan?style=social)](https://github.com/tianlusec/TL-ICScan)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING_EN.md)

> **Open Source Security Intelligence Tool** | Localized | Multi-source Aggregation | Smart Analysis
>
> This repository contains the complete open-source code and collection scripts for TL-ICScan.
>
> **TL-ICScan is developed and maintained as open source by Tianlu Laboratory.**

[中文版](README.md) ← Chinese primary

## Latest Update (v0.6.0)

**Release Date**: December 11, 2025

This update includes major improvements and bug fixes:

### New Features
- **Unified Configuration Management**: New `config.py` module with environment variable support
- **Unified Logging System**: All modules use standard logging with level control
- **Error Code System**: Unified error codes (E001-E999) for easier troubleshooting
- **Improved Configuration Examples**: `watchlist.yml` includes 4 detailed examples with complete field descriptions
- **Unit Tests**: New collector unit tests for improved reliability

### Bug Fixes
- Fixed timezone handling inconsistency (unified to UTC)
- Fixed memory growth risk (added 10KB limit per value)
- Fixed NVD data collection checkpoint mechanism
- Fixed GitHub API rate limit handling
- Fixed CSV export injection protection
- Fixed database connection management

### Performance Improvements
- Optimized batch commit size (from 100 to 500)
- Added database composite indexes for better query performance
- Improved caching strategy with configurable TTL via environment variables

### Documentation Improvements
- Added detailed version requirements
- Completed OS support list
- Improved configuration file error messages
- Updated contribution guidelines

For detailed changelog, see [CHANGELOG_EN.md](docs/CHANGELOG_EN.md) | [中文版](docs/CHANGELOG.md)

---

## Introduction

TL-ICScan is a **localized vulnerability intelligence aggregation and analysis tool** developed by **Tianlu Laboratory**, designed for security researchers, Red Teams, and Blue Teams.

**How it Works (In a Nutshell):**
> **Python "Fetches", Rust "Manages".**
>
> *   **Python (Collector)**: Acts as a diligent procurement agent, fetching the latest vulnerability intelligence from NVD, GitHub, Exploit-DB, etc., and "translating" them into a unified format.
> *   **Rust (Core Engine)**: Acts as an efficient warehouse manager, rapidly storing the massive data fetched by Python into a local database and providing millisecond-level query services.
> *   **Web UI (Dashboard)**: Reads directly from the local database, offering an offline, instant, and visual query experience.

In daily security operations and research, we face challenges such as fragmented intelligence sources (NVD, CISA, Vendor Advisories, Exploit-DB), inconsistent data formats, and over-reliance on online queries. TL-ICScan aims to solve these problems:

- **Multi-source Aggregation**: Automatically collects and standardizes intelligence from NVD, CISA KEV, MSRC, Exploit-DB, GitHub PoC, and more.
- **Local & Private**: All data is stored in a local SQLite database, allowing offline queries and ensuring operational stealth.
- **Smart Correlation**: Automatically correlates PoC status, EPSS scores, and vendor advisories to provide a "God Mode" view.
- **Pure Intelligence**: Focuses solely on "intelligence" itself, without binding to asset management, remaining lightweight and easy to integrate.
- **Cross-Platform**: Native support for Windows, Linux, and macOS with a unified CLI experience.

![TL-ICScan Dashboard](docs/images/dashboard_preview.png)

---

## Key Features

1.  **Multi-source Collection (Collectors)**: Modular Python scripts supporting NVD, CISA KEV, MSRC, Exploit-DB, EPSS, GitHub PoC, etc.
2.  **Data Standardization**: Cleans heterogeneous data into a unified `NormalizedCVE` format (JSONL).
3.  **High-performance Storage**: Rust core engine handles data ingestion and indexing, supporting sub-second queries for millions of records.
4.  **Smart Digest**: Automatically generates daily/weekly vulnerability briefings in Markdown based on a YAML `watchlist`.
5.  **Flexible Export**: Supports export to JSON/CSV formats for easy import into Excel or other analysis tools.

---

## Quick Start

### Method 1: Docker Deployment (Recommended)

No need to install Rust or Python environments. Start everything with Docker.

1. **Start Services**
   ```bash
   docker-compose up -d
   ```
   Access the Web UI at http://localhost:8501.

2. **Update Data**
   ```bash
   # Run a one-time update task
   docker-compose run --rm updater
   ```

### Method 2: Source Installation

#### 1. Prerequisites

- **Rust**: For compiling the core tool (`cargo build --release`)
    - **Version Requirement**: Rust 1.70 or higher
- **Python**: For running collection scripts
    - **Version Requirement**: Python 3.8 or higher
- **Supported Operating Systems**:
    - Windows 10/11 (x64)
    - Linux (Ubuntu 20.04+, CentOS 7+, Debian 10+)
    - macOS (Intel/Apple Silicon)

#### 2. Installation

```bash
# 1. Build the core tool
cd tianlu-intel-core
cargo build --release
# The binary is located at target/release/tianlu-intel-core (or .exe on Windows)

# 2. Install collector dependencies
cd ../tianlu_intel_collectors
pip install -e .
```

#### 3. Initialization & Update

We provide a one-click update script that automatically runs all collectors and imports data into the database (`tianlu_intel_v2.db`).

- **Windows**: Run `update_all.bat`
- **Linux/macOS**: Run `./update_all.sh`

#### 4. Common Commands

All operations are done via the CLI tool (assuming you are in the project root directory):

**Start Web UI (Dashboard)**
```bash
# Start the Web interface, default access at http://localhost:8501
streamlit run web_ui/dashboard.py
```

**Query Vulnerability List**
```bash
# Query high-severity vulnerabilities published in the last 7 days
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

## Contributing & Support

We warmly welcome all forms of contributions! TL-ICScan is an open-source project that relies on the community to continuously improve.

### How to Contribute

- **Submit Issues**: Report bugs, suggest new features, or share your experience
- **Submit Pull Requests**: Contribute code, documentation, or test cases
  - Please read the [Contributing Guide](CONTRIBUTING_EN.md) first to understand development standards
  - Ensure code passes all tests and follows project style
- **Improve Documentation**: Help improve docs, add examples, or translate
- **Report Security Issues**: Responsibly disclose security vulnerabilities, see [Security Policy](SECURITY_EN.md)
- **Star the Project**: If you find it useful, give us a star to support the project!
- **Share Feedback**: Share your use cases and suggestions in Discussions

### Contributors

Thanks to all developers who have contributed to TL-ICScan!

<!-- Contributors list will be automatically updated -->

### Open Source License

This project is licensed under the MIT License, which allows you to:
- Commercial use
- Modify source code
- Distribute copies
- Private use

The only requirement is to retain the original license and copyright notice. See [LICENSE](LICENSE) for details.

## Project Status

- **Development Status**: Actively maintained
- **Stability**: Production-ready
- **Test Coverage**: Continuously improving
- **Documentation**: Complete

## Acknowledgments

Thanks to the following projects and organizations for providing data sources:
- [NVD](https://nvd.nist.gov/) - National Vulnerability Database
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - Known Exploited Vulnerabilities
- [Exploit-DB](https://www.exploit-db.com/) - Exploit Database
- [EPSS](https://www.first.org/epss/) - Exploit Prediction Scoring System
- [Microsoft MSRC](https://msrc.microsoft.com/) - Microsoft Security Response Center

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=tianlusec/TL-ICScan&type=Date)](https://star-history.com/#tianlusec/TL-ICScan&Date)

## Contact Us

- **Project Homepage**: [GitHub Repository](https://github.com/tianlusec/TL-ICScan)
- **Issue Tracker**: [GitHub Issues](https://github.com/tianlusec/TL-ICScan/issues)
- **Feature Discussions**: [GitHub Discussions](https://github.com/tianlusec/TL-ICScan/discussions)
- **Security Reports**: See [SECURITY_EN.md](SECURITY_EN.md)

## License

This project is licensed under the [MIT License](LICENSE).

```
MIT License

Copyright (c) 2024-2025 Tianlu Laboratory

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

**Developed and maintained as open source by Tianlu Laboratory**

*Making Vulnerability Intelligence Accessible*
