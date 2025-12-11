# TL-ICScan —  (Roadmap)

> ""

[English Version](ROADMAP_EN.md)

---

##  v0.1 — 

 `NormalizedCVE` SQLite CLI  CRUD /  / 



-  `update_all`  NVD/KEV
- `ingest`  `cve_id`  `sources` 
- CLI  `init-db``ingest``list``show``export``digest`



- Python Collector  JSONL `NormalizedCVE` JSON
- Rust `ingest`  stdin 

****: 2024-04-01

---

##  v0.2 — 

 CLI 



- `cwe_ids`JSON  NVD/
- `attack_vector`, `privileges_required`, `user_interaction` CVSS
- `confidentiality_impact` / `integrity_impact` / `availability_impact`
- `is_in_kev` CISA KEV
- `exploit_exists` Exploit-DB / KEV /  PoC 
- `epss_score` / `epss_percentile` EPSS Collector

CLI 

- `--cwe CWE-89`
- `--attack-vector NETWORK`
- `--vendor` / `--product` CPE  vendors/products 
- `--epss-min 0.1` EPSS 
- `--has-exploit` / `--in-kev`



- “”
- vendors, products, references, poc_sources

“ 30 HIGH PoC”

****: 2024-06-01

---

##  v0.3 — 



 Collector

1. Microsoft MSRC
2. Exploit-DBPoC 
3. CNNVD / CNVD 



-  Collector  JSONL `feed_version``download_hash`
- `ingest`  `sources`  `{name, first_seen, last_seen, feed_version}`

 `cve_id`  `show` 

****: 2024-08-15

---

##  v0.4 — Watchlist  Digest 

 watchlist Markdown 



- `watchlist.yml`  `name``vendors``products``keywords``severity_min``epss_min` 
- `digest`  watchlist 

 watchlist 

```yaml
- name: windows_core
  vendors: ["microsoft"]
  products: ["windows_server", "exchange"]
  severity_min: HIGH
  epss_min: 0.2
```

 `digest --config watchlist.yml --since 1d`  Markdown 

****: 2024-10-01

---

##  v0.5 — PoC 

 PoC  exploit `poc_risk_label``poc_repo_count` feed 

****: 2024-11-15



- [x]  CollectorGitHub  / Exploit-DB 
- [x]  PoC  `stars`, `forks`, `last_update` `trusted/unknown/suspicious` 
- [x]  DB  `download_hash`  `feed_version` 

  `show`  PoC  feed

---

##  v0.6 — 

****: 2025-12-11





- [x] `config.py` 
- [x]  logging 
- [x] E001-E999
- [x] 
- [x] 
- [x] Bug API 
- [x] Web UI Streamlit 
- [x] CHANGELOG

 

---

##  v0.7 — Web UI 

****: 2025 Q1

 Web UI 



- [ ] Watchlist 
- [ ] 
- [ ] 
- [ ] 
- [ ] 
- [ ] 

Web UI  DB  API  UI  PoC 

---

##  v0.8 — 

****: 2025 Q2





- [ ] 
- [ ] IOC 
- [ ] 
- [ ] Webhook 
- [ ] REST API 
- [ ] 

---

##  v1.0 — 

****: 2025 Q3-Q4





- [ ] >80%
- [ ] 
- [ ] i18n
- [ ] 
- [ ]  API 
- [ ] 

---

## 



-   [GitHub Issues](https://github.com/tianlusec/TL-ICScan/issues) 
-   [GitHub Discussions](https://github.com/tianlusec/TL-ICScan/discussions) 
-   Pull Request 
-  

## 

###  DB Schema

- `init-db`  ALTER
- 
- 

### Collector 

 Collector 
-  JSONL 
- 
- 
- 
- 

### Pull Request 

PR 
- 
- 
- 
-  Issue 

---

****

