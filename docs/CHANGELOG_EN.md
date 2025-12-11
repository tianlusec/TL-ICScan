# Changelog

All notable changes to the TL-ICScan project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.6.0] - 2025-12-11

### New Features

- **Unified Configuration Management**: New [`config.py`](../tianlu_intel_collectors/tianlu_intel_collectors/config.py) module
  - Support configuration via environment variables for API keys and parameters
  - Centralized management of all collector configurations
  - Configuration validation and default value mechanism

- **Unified Logging System**: All modules use standard Python logging
  - Support log level control via `LOG_LEVEL` environment variable
  - Unified log format and output
  - Improved error tracking capabilities

- **Error Code System**: Unified error code definitions (E001-E999)
  - E001-E099: Configuration-related errors
  - E100-E199: Network request errors
  - E200-E299: Data parsing errors
  - E300-E399: Database operation errors
  - E400-E499: File operation errors
  - Easier problem identification and troubleshooting

- **Improved Configuration Examples**: [`watchlist.yml`](../watchlist.yml) with detailed examples
  - 4 practical monitoring scenario examples
  - Complete field descriptions and comments
  - Best practice recommendations

- **Unit Tests**: New collector unit tests
  - Test coverage for main collector modules
  - Improved code reliability and maintainability

### Bug Fixes

- **Timezone Handling**: Fixed timezone inconsistency issues
  - Unified UTC time storage
  - Fixed cross-timezone query errors
  - Improved timestamp parsing logic

- **Memory Management**: Fixed memory growth risks
  - Added 10KB size limit per field value
  - Optimized large data processing
  - Prevented memory overflow

- **NVD Collection**: Fixed checkpoint mechanism
  - Improved incremental update logic
  - Fixed duplicate data issues
  - Optimized API call strategy

- **GitHub API**: Fixed rate limit handling
  - Improved API throttling detection
  - Added automatic retry mechanism
  - Optimized request frequency control

- **CSV Export**: Fixed injection protection
  - Added CSV injection protection
  - Escaped special characters
  - Improved export security

- **Database Connection**: Fixed connection management issues
  - Improved connection pool management
  - Fixed connection leaks
  - Optimized concurrent access

### Performance Improvements

- **Batch Commits**: Optimized batch commit size (from 100 to 500)
  - Significantly improved data import speed
  - Reduced database transaction overhead

- **Database Indexes**: Added composite indexes
  - Optimized common query performance
  - Improved multi-condition filtering speed
  - Reduced query response time

- **Caching Strategy**: Improved caching mechanism
  - Support TTL configuration via environment variables
  - Optimized cache hit rate
  - Reduced duplicate requests

### Documentation Improvements

- Added detailed version requirements (Rust 1.70+, Python 3.8+)
- Completed OS support list (Windows/Linux/macOS)
- Improved configuration file error messages and examples
- Updated contribution guidelines and development standards
- Added more usage examples and best practices

### Other Changes

- Updated dependency package versions
- Improved error message readability
- Optimized command-line argument parsing
- Enhanced type hints and docstrings

---

## [0.5.0] - 2024-11-15

### New Features

- Added GitHub PoC collector
- Added Exploit-DB collector
- Implemented PoC risk grading functionality
- Added data source version tracking

### Bug Fixes

- Fixed EPSS data parsing errors
- Fixed MSRC advisory collection issues
- Improved error handling mechanism

### Performance Improvements

- Optimized database query performance
- Improved concurrent collection efficiency

---

## [0.4.0] - 2024-10-01

### New Features

- Implemented Watchlist configuration functionality
- Added Digest intelligence briefing generation
- Support for Markdown format output
- Added multi-condition filtering

### Documentation Improvements

- Added Watchlist configuration guide
- Completed CLI usage documentation

---

## [0.3.0] - 2024-08-15

### New Features

- Added MSRC collector
- Added EPSS score collection
- Implemented multi-source data merging
- Support for vendor advisory correlation

### Bug Fixes

- Fixed data duplication issues
- Improved CPE parsing logic

---

## [0.2.0] - 2024-06-01

### New Features

- Extended CVE fields (CWE, detailed CVSS information)
- Added advanced query filters
- Support for JSON/CSV export
- Added CISA KEV collector

### Performance Improvements

- Optimized database indexes
- Improved query performance

---

## [0.1.0] - 2024-04-01

### New Features

- Initial release
- Implemented NVD data collection
- Implemented data standardization (NormalizedCVE)
- Implemented Rust core engine (data ingestion, querying)
- Provided basic CLI commands (init-db, ingest, list, show)
- Implemented SQLite local storage

---

## Version Numbering

- **Major version**: Incompatible API changes
- **Minor version**: Backward-compatible functionality additions
- **Patch version**: Backward-compatible bug fixes

## Contributing

Issues and Pull Requests are welcome! See [CONTRIBUTING_EN.md](../CONTRIBUTING_EN.md) for details.