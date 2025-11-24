# TL-ICScan — Roadmap

> This roadmap is intended for developers and collaborators, describing features, implementation suggestions, and acceptance criteria version by version. The goal is always "only collecting, cleaning, and providing intelligence, not involving assets or automated response".

---

## v0.1 — Basic Version (Implemented/Designed)

Goal: Complete data fetching from sources, standardization into `NormalizedCVE`, ingestion into SQLite, and provide basic CRUD / Export / Digest via CLI.

Acceptance Criteria:

- Can pull and ingest NVD/KEV in one go via `update_all` script.
- `ingest` can merge multi-source data for the same `cve_id` and preserve the `sources` list.
- CLI provides `init-db`, `ingest`, `list`, `show`, `export`, `digest`.

Implementation Points:

- Python Collector outputs JSONL (one `NormalizedCVE` JSON per line).
- Rust `ingest` reads from stdin and executes transactional batch writes.

---

## v0.2 — Field Extension and Query Enhancement

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

---

## v0.3 — Multi-source Extension (Geography and Vendor)

Goal: Extend more intelligence sources (National, Vendor, Third-party research), support multi-perspective comparison.

Priority New Collectors (Suggested Order):

1. Microsoft MSRC (Vendor announcement structure is stable)
2. Exploit-DB (PoC metadata)
3. CNNVD / CNVD or other national databases (depending on availability)

Implementation Suggestions:

- Each Collector outputs example JSONL (including `feed_version`, `download_hash`).
- `ingest` records `sources` details (e.g., `{name, first_seen, last_seen, feed_version}`).

Acceptance Criteria: Can see multi-source records for the same `cve_id` and display differences between sources in `show`.

---

## v0.4 — Watchlist and Digest Reports

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

---

## v0.5 — PoC Risk Grading and Data Quality

Goal: Add quality and credibility labels (`poc_risk_label`, `poc_repo_count`) for PoC and exploit links, and save feed version information for traceability.

Implementation Points:

- New Collector: GitHub Search / Exploit-DB Metadata Collection (Collect meta-info only, do not clone or execute).
- Record `stars`, `forks`, `last_update` for each PoC, and give `trusted/unknown/suspicious` labels based on simple rules (static metrics).
- Save `download_hash` and `feed_version` fields for key sources in DB.

Acceptance Criteria: Display PoC source and its risk label in `show` output, and data can be traced back to the collection feed.

---

## v0.6 — Web UI (Optional, Not Required)

Goal: Provide a lightweight frontend dashboard for end-users, displaying digest, search, and watchlist management (Backend continues to remain CLI-first).

Implementation Suggestions:

- Use static frontend (React/Vue) + a small backend (Rust warp/axum or Python FastAPI) as read-only API.
- Priority: Filter page (vendor/product/epss/cwe), digest browsing, watchlist management.

Compliance Suggestion: Web UI should only read DB or provide data via exported API, and not implement any PoC execution functions within the UI.

---

## Developer Guide (Additional Notes)

- When adding new fields or changing DB schema, please submit migration instructions (`init-db` will try to do simple ALTER, but complex migrations need manual instructions).
- Collector output example (should be included in each Collector README): Example JSONL, field description, collection frequency.
- PR template suggested to include: Change summary, test steps, rollback method.
