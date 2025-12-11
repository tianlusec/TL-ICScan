# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2025-12-11

### Added
- **Unified Configuration**: Added `config.py` module with environment variable support.
- **Unified Logging**: Implemented standard logging across all modules with level control.
- **Error Codes**: Defined unified error codes (E001-E999) for better troubleshooting.
- **Configuration Examples**: Enhanced `watchlist.yml` with 4 detailed examples and field descriptions.
- **Unit Tests**: Added unit tests for collectors to improve reliability.
- **Docker Support**: Added `Dockerfile` and `docker-compose.yml` for one-click deployment.

### Fixed
- Fixed inconsistent timezone handling (unified to UTC).
- Fixed memory growth risk (added 10KB limit per value).
- Fixed NVD data collection resume mechanism.
- Fixed GitHub API rate limit handling.
- Fixed CSV export injection protection.
- Fixed database connection management issues.

### Performance
- Optimized batch commit size (increased from 100 to 500).
- Added composite database indexes to improve query performance.
- Improved caching strategy with configurable TTL.

### Documentation
- Added detailed version requirements.
- Updated supported operating systems list.
- Improved configuration file error messages.
- Updated contribution guidelines.
- Removed emojis from all documentation for a more professional style.
