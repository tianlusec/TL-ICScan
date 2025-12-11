# TL-ICScan — Roadmap

> This roadmap is intended for developers and collaborators, describing features, implementation suggestions, and acceptance criteria version by version. The goal is always "only collecting, cleaning, and providing intelligence, not involving assets or automated response".

[](ROADMAP.md)

---

##  v0.1 — Basic Version (Completed)

Goal: Complete data fetching from sources, standardization into `NormalizedCVE`, ingestion into SQLite, and provide basic CRUD / Export / Digest via CLI.

Acceptance Criteria:

- Can pull and ingest NVD/KEV in one go via `update_all` script.
- `ingest` can merge multi-source data for the same `cve_id` and preserve the `sources` list.
- CLI provides `init-db`, `ingest`, `list`, `show`, `export`, `digest`.

Implementation Points:

- Python Collector outputs JSONL (one `NormalizedCVE` JSON per line).
- Rust `ingest` reads from stdin and executes transactional batch writes.

**Release Date**: April 1, 2024

---

##  v0.2 — Field Extension and Query Enhancement (Completed)

Goal: Add more filterable intelligence fields based on existing data and expose rich filtering conditions in the CLI.

New Fields (Examples) and Sources:

- `cwe_ids` (JSON array, source NVD/Vendor)
- `attack_vector`, `privileges_required`, `user_interaction` (Source CVSS)
- `confidentiality_impact` / `integrity_impact` / `availability_impact`
- `is_in_kev` (Source CISA KEV)
- `exploit_exists` (From Exploit-DB / KEV / Other PoC indicators)
- `epss_score` / `epss_percentile` (From EPSS Collector)

CLI Extensions (Must Implement):

- `--cwe CWE-89`
- `--attack-vector NETWORK`
- `--vendor` / `--product` (vendors/products fields based on CPE parsing)
- `--epss-min 0.1` (Filter by EPSS threshold)
- `--has-exploit` / `--in-kev`

Merge Strategy:

- Use "new value overwrites old value" strategy for scalar values (if the new source field is not empty).
- Union and deduplicate array fields (vendors, products, references, poc_sources).

Acceptance Criteria: Can obtain a list of "last 30 days, HIGH severity, NETWORK vector, and has PoC" through combined filtering.

**Release Date**: June 1, 2024

---

##  v0.3 — Multi-source Extension (Geography and Vendor) (Completed)

Goal: Extend more intelligence sources (National, Vendor, Third-party research), support multi-perspective comparison.

Priority New Collectors (Suggested Order):

1. Microsoft MSRC (Vendor announcement structure is stable)
2. Exploit-DB (PoC metadata)
3. CNNVD / CNVD or other national databases (depending on availability)

Implementation Suggestions:

- Each Collector outputs example JSONL (including `feed_version`, `download_hash`).
- `ingest` records `sources` details (e.g., `{name, first_seen, last_seen, feed_version}`).

Acceptance Criteria: Can see multi-source records for the same `cve_id` and display differences between sources in `show`.

**Release Date**: August 15, 2024

---

##  v0.4 — Watchlist and Digest Reports (Completed)

Goal: Implement configurable watchlist, automatically generate Markdown format intelligence daily reports.

Feature Points:

- `watchlist.yml` supports fields like `name`, `vendors`, `products`, `keywords`, `severity_min`, `epss_min`.
- `digest` command generates sectioned reports for each watchlist entry and supports output to file.

Example watchlist entry:

```yaml
- name: windows_core
  vendors: ["microsoft"]
  products: ["windows_server", "exchange"]
  severity_min: HIGH
  epss_min: 0.2
```

Acceptance Criteria: Users can get a Markdown report classified by watchlist items via `digest --config watchlist.yml --since 1d`.

**Release Date**: October 1, 2024

---

##  v0.5 — PoC Risk Grading and Data Quality (Completed)

Goal: Add quality and credibility labels (`poc_risk_label`, `poc_repo_count`) for PoC and exploit links, and save feed version information for traceability.

**Release Date**: November 15, 2024

Implementation Points:

- [x] New Collector: GitHub Search / Exploit-DB Metadata Collection (Collect meta-info only, do not clone or execute)
- [x] Record `stars`, `forks`, `last_update` for each PoC, and give `trusted/unknown/suspicious` labels based on simple rules (static metrics)
- [x] Save `download_hash` and `feed_version` fields for key sources in DB

Acceptance Criteria:  Display PoC source and its risk label in `show` output, and data can be traced back to the collection feed.

---

##  v0.6 — Unified Configuration and Quality Improvements (Completed)

**Release Date**: December 11, 2025

Goal: Improve code quality, unify configuration management, enhance error handling and logging system.

Implementation Points:

- [x] Unified configuration management (`config.py` module)
- [x] Unified logging system (standard logging module)
- [x] Error code system (E001-E999)
- [x] Unit test coverage
- [x] Performance optimization (batch commits, index optimization)
- [x] Bug fixes (timezone, memory, API rate limiting, etc.)
- [x] Web UI basic features (Streamlit dashboard)
- [x] Documentation improvements (CHANGELOG, contribution guide, etc.)

Acceptance Criteria:  All core features run stably, code quality significantly improved, documentation complete.

---

##  v0.7 — Web UI Enhancement (Planned)

**Expected Release**: Q1 2025

Goal: Enhance Web UI functionality to provide richer interactive experience.

Planned Features:

- [ ] Watchlist visual management interface
- [ ] Advanced charts and statistical analysis
- [ ] Vulnerability trend analysis
- [ ] Custom dashboard layout
- [ ] Enhanced report export functionality
- [ ] User preference settings

Compliance Suggestion: Web UI should only read DB or provide data via exported API, and not implement any PoC execution functions within the UI.

---

##  v0.8 — Advanced Analysis and Integration (Planning)

**Expected Release**: Q2 2025

Goal: Provide more advanced analysis features and third-party integrations.

Planned Features:

- [ ] Vulnerability correlation analysis (attack chain analysis)
- [ ] Threat intelligence correlation (IOC correlation)
- [ ] Machine learning risk prediction
- [ ] Webhook notification support
- [ ] REST API interface
- [ ] Plugin system architecture

---

##  v1.0 — Stable Release (Long-term Goal)

**Expected Release**: Q3-Q4 2025

Goal: Achieve production-grade stability, complete features, comprehensive documentation.

Milestones:

- [ ] Complete test coverage (>80%)
- [ ] Performance benchmarking
- [ ] Multi-language support (i18n)
- [ ] Enterprise deployment guide
- [ ] Complete API documentation
- [ ] Community ecosystem building

---

## Contribute Your Ideas

We welcome community suggestions for new features! Participate through:

-  Submit feature requests in [GitHub Issues](https://github.com/tianlusec/TL-ICScan/issues)
-  Join discussions in [GitHub Discussions](https://github.com/tianlusec/TL-ICScan/discussions)
-  Submit Pull Requests to implement new features
-  Improve documentation and examples

## Developer Guide

### Adding New Fields or Changing DB Schema

- Submit migration instructions (`init-db` will try to do simple ALTER, but complex migrations need manual instructions)
- Update related documentation and test cases
- Consider backward compatibility

### Collector Development Standards

Each Collector should include:
- Example JSONL output
- Field description documentation
- Collection frequency recommendations
- Error handling mechanism
- Unit tests

### Pull Request Standards

PRs should include:
- Change summary
- Test steps
- Rollback method
- Related Issue links

---

**The roadmap will be dynamically adjusted based on community feedback and actual needs.**
