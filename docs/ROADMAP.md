# TL-ICScan — Roadmap

> 这份 roadmap 面向开发者与协作者，按版本逐步描述功能、实现建议与验收标准。目标始终是“只做情报的收集、清洗与提供，不涉及资产或自动响应”。

---

## v0.1 — 基础版（已实现/设计）

目标：完成从来源拉取数据、标准化为 `NormalizedCVE`、入库到 SQLite，并通过 CLI 提供基础 CRUD / 导出 / 简报。

验收标准：

- 能通过 `update_all` 脚本一次性拉取并入库 NVD/KEV。
- `ingest` 能合并同一 `cve_id` 的多源数据且保留 `sources` 列表。
- CLI 提供 `init-db`、`ingest`、`list`、`show`、`export`、`digest`。

实现要点：

- Python Collector 输出 JSONL（每行一个 `NormalizedCVE` JSON）。
- Rust `ingest` 从 stdin 读取并执行事务批量写入。

---

## v0.2 — 字段扩展与查询增强

目标：在现有数据基础上增加更多可筛选的情报字段并在 CLI 中暴露丰富过滤条件。

新字段（示例）与来源：

- `cwe_ids`（JSON 数组，来源 NVD/厂商）
- `attack_vector`, `privileges_required`, `user_interaction`（来源 CVSS）
- `confidentiality_impact` / `integrity_impact` / `availability_impact`
- `is_in_kev`（来源 CISA KEV）
- `exploit_exists`（来自 Exploit-DB / KEV / 其他 PoC 指标）
- `epss_score` / `epss_percentile`（来自 EPSS Collector）

CLI 扩展（必须实现）：

- `--cwe CWE-89`
- `--attack-vector NETWORK`
- `--vendor` / `--product`（基于 CPE 解析的 vendors/products 字段）
- `--epss-min 0.1`（按 EPSS 阈值筛选）
- `--has-exploit` / `--in-kev`

合并策略：

- 对标量值采用“新值覆盖旧值”策略（如果新来源字段非空）。
- 对数组字段（vendors, products, references, poc_sources）做并集去重。

验收标准：能通过组合过滤得到“最近 30 天，高危（HIGH），网络向量且有 PoC”的列表。

---

## v0.3 — 多源扩展（地理与厂商）

目标：扩展更多情报源（国家级、厂商、第三方研究），支持多视角对比。

优先新增 Collector（建议顺序）：

1. Microsoft MSRC（厂商公告结构稳定）
2. Exploit-DB（PoC 元数据）
3. CNNVD / CNVD 或其他国家级库（视可用性）

实现建议：

- 每个 Collector 输出示例 JSONL（包含 `feed_version`、`download_hash`）。
- `ingest` 记录 `sources` 细节（例如 `{name, first_seen, last_seen, feed_version}`）。

验收标准：能看到同一 `cve_id` 的多源记录并在 `show` 中显示各源差异。

---

## v0.4 — Watchlist 与 Digest 报表

目标：实现可配置的 watchlist，自动化生成 Markdown 格式的情报日报。

功能要点：

- `watchlist.yml` 支持 `name`、`vendors`、`products`、`keywords`、`severity_min`、`epss_min` 等字段。
- `digest` 命令为每个 watchlist 条目生成分节报表并支持输出到文件。

示例 watchlist 条目：

```yaml
- name: windows_core
  vendors: ["microsoft"]
  products: ["windows_server", "exchange"]
  severity_min: HIGH
  epss_min: 0.2
```

验收标准：用户能通过 `digest --config watchlist.yml --since 1d` 得到按关注项分类的 Markdown 报表。

---

## v0.5 — PoC 风险分级与数据质量（部分已实现）

目标：为 PoC 与 exploit 链接增加质量与可信度标签（`poc_risk_label`、`poc_repo_count`），并保存 feed 的版本信息以便溯源。

实现要点：

- [x] 新增 Collector：GitHub 搜索 / Exploit-DB 元数据采集（仅收集元信息，不克隆或执行）。
- [ ] 为每个 PoC 记录 `stars`, `forks`, `last_update`，并根据简单规则给出 `trusted/unknown/suspicious` 标签（静态指标）。
- [ ] 在 DB 中为关键源保存 `download_hash` 与 `feed_version` 字段。

验收标准：在 `show` 输出中显示 PoC 源与其风险标签，且数据可追溯到采集 feed。

---

## v0.6 — Web UI（可选，非必须）

目标：为终端用户提供一个轻量级的前端仪表盘，展示 digest、搜索与 watchlist 管理（后端继续保持 CLI-first）。

实现建议：

- 使用静态前端（React/Vue） + 一个小型后端（Rust warp/axum 或 Python FastAPI）作为只读 API。
- 优先做：筛选页面（vendor/product/epss/cwe）、digest 浏览、watchlist 管理。

合规建议：Web UI 应只读访问 DB 或通过导出的 API 提供数据，不在 UI 内实现任何 PoC 执行功能。

---

## 开发者指南（额外说明）

- 新增字段或变更 DB schema 时，请提交迁移说明（`init-db` 会尝试做简单 ALTER，但复杂迁移需手动说明）。
- Collector 的输出示例（每个 Collector README 中应包含）：示例 JSONL、字段说明、采集频率。
- PR 模板建议包含：变更摘要、测试步骤、回滚方法。

