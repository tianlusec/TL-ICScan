# TL-ICScan 漏洞情报聚合与分析工具

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Rust 1.70+](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![GitHub release](https://img.shields.io/github/v/release/tianlusec/TL-ICScan)](https://github.com/tianlusec/TL-ICScan/releases)
[![GitHub stars](https://img.shields.io/github/stars/tianlusec/TL-ICScan?style=social)](https://github.com/tianlusec/TL-ICScan)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

> **开源安全情报工具** | 本地化 | 多源聚合 | 智能分析
>
> 本仓库为 TL-ICScan 的完整开源代码与采集脚本集合。
>
> **TL-ICScan 由天禄实验室开发并开源维护。**

[English Version](README_EN.md) ← 中文为主体

## 最新更新 (v0.6.0)

**发布日期**: 2025-12-11

本次更新包含重大改进和bug修复：

### 新特性
- **统一配置管理**: 新增 `config.py` 模块，支持环境变量配置
- **统一日志系统**: 所有模块使用标准 logging 模块，支持日志级别控制
- **错误码体系**: 新增统一的错误码定义（E001-E999），便于问题排查
- **改进的配置示例**: `watchlist.yml` 包含4个详细示例和完整字段说明
- **单元测试**: 新增采集器单元测试，提高代码可靠性

### Bug修复
- 修复时区处理不一致问题（统一使用UTC）
- 修复内存增长风险（添加单个值10KB限制）
- 修复NVD数据采集断点续传机制
- 修复GitHub API速率限制处理
- 修复CSV导出注入防护
- 修复数据库连接管理问题

### 性能优化
- 优化批量提交大小（从100提升到500）
- 添加数据库复合索引，提升查询性能
- 改进缓存策略，支持环境变量配置TTL

### 文档改进
- 添加详细的版本要求说明
- 完善操作系统支持列表
- 改进配置文件错误提示
- 更新贡献指南

详细更新日志请查看 [CHANGELOG.md](docs/CHANGELOG.md) | [English Version](docs/CHANGELOG_EN.md)

---

## 项目简介

TL-ICScan 是由**天禄实验室**开发的一款面向安全研究人员、红队与蓝队的**本地化漏洞情报聚合与分析工具**。

**一句话原理解析：**
> **Python 负责“进货”，Rust 负责“管库”。**
> 
> *   **Python (采集端)**：像勤劳的采购员，去 NVD、GitHub、Exploit-DB 等网站抓取最新的漏洞情报，并把它们“翻译”成统一格式。
> *   **Rust (核心库)**：像高效的仓库管理员，负责把 Python 抓回来的海量数据快速存入本地数据库，并提供毫秒级的查询服务。
> *   **Web UI (展示端)**：直接读取本地数据库，为您提供无需联网、随查随有的可视化查询体验。

在日常的安全运营与研究中，我们面临着情报源分散（NVD, CISA, 厂商公告, Exploit-DB）、数据格式不统一、以及过度依赖在线查询等痛点。TL-ICScan 旨在解决这些问题：

- **多源聚合**：自动采集并标准化 NVD、CISA KEV、MSRC、Exploit-DB、GitHub PoC 等多方情报。
- **本地私有**：所有数据存储于本地 SQLite 数据库，查询无需联网，保障操作隐蔽性。
- **智能关联**：自动关联漏洞的 PoC 状态、EPSS 评分与厂商公告，提供上帝视角。
- **纯粹情报**：专注于“情报”本身，不绑定资产管理，轻量级且易于集成。
- **全平台支持**：原生支持 Windows、Linux 与 macOS，提供统一的 CLI 操作体验。

![TL-ICScan Dashboard](docs/images/dashboard_preview.png)

---

## 核心功能

1.  **多源采集 (Collectors)**: 模块化 Python 脚本，支持 NVD, CISA KEV, MSRC, Exploit-DB, EPSS, GitHub PoC 等。
2.  **数据标准化**: 将异构数据清洗为统一的 `NormalizedCVE` 格式 (JSONL)。
3.  **高性能存储**: Rust 核心引擎处理数据入库与索引，支持百万级记录秒级查询。
4.  **智能简报 (Digest)**: 基于 YAML 配置关注列表 (Watchlist)，自动生成 Markdown 格式的每日/每周漏洞简报。
5.  **灵活导出**: 支持导出为 JSON/CSV 格式，便于导入 Excel 或其他分析工具。

---

## 快速开始

### 方式一：Docker 部署 (推荐)

无需安装 Rust 和 Python 环境，直接使用 Docker 一键启动。

1. **启动服务**
   ```bash
   docker-compose up -d
   ```
   访问 http://localhost:8501 即可看到 Web 界面。

2. **更新数据**
   ```bash
   # 运行一次性更新任务
   docker-compose run --rm updater
   ```

### 方式二：源码安装

#### 1. 环境准备

- **Rust**: 用于编译核心工具 (`cargo build --release`)
    - **版本要求**: Rust 1.70 或更高版本
- **Python**: 用于运行采集脚本
    - **版本要求**: Python 3.8 或更高版本
- **操作系统支持**:
    - Windows 10/11 (x64)
    - Linux (Ubuntu 20.04+, CentOS 7+, Debian 10+)
    - macOS (Intel/Apple Silicon)

#### 2. 安装

```bash
# 1. 编译核心工具
cd tianlu-intel-core
cargo build --release
# 编译产物位于 target/release/tianlu-intel-core (Windows 为 .exe)

# 2. 安装依赖
# 在项目根目录下运行
pip install -r requirements.txt
```

#### 3. 初始化与更新数据

我们提供了一键更新脚本，会自动运行所有采集器并将数据导入数据库 (`tianlu_intel_v2.db`)。

- **Windows**: 运行 `update_all.bat`
- **Linux/macOS**: 运行 `./update_all.sh`

#### 4. 常用命令

所有操作通过 CLI 工具完成（假设位于项目根目录）：

**启动 Web UI (可视化仪表盘)**
```bash
# 启动 Web 界面，默认访问 http://localhost:8501
streamlit run web_ui/dashboard.py
```

**查询漏洞列表**
```bash
# 查询最近 7 天发布的的高危漏洞
./tianlu-intel-core/target/release/tianlu-intel-core list --since 7d --severity HIGH --db tianlu_intel_v2.db
```

**查看漏洞详情**
```bash
# 查看特定 CVE 的详细情报（包含描述、CVSS、PoC、参考链接等）
./tianlu-intel-core/target/release/tianlu-intel-core show CVE-2024-12345 --db tianlu_intel_v2.db
```

**生成情报简报**
```bash
# 根据 watchlist.yml 生成简报
./tianlu-intel-core/target/release/tianlu-intel-core digest --config watchlist.yml --since 1d --db tianlu_intel_v2.db
```

---

## 配置说明 (Watchlist)

通过修改 `watchlist.yml` 定制您关注的情报：

```yaml
- name: "Windows 核心组件"
  vendors: ["microsoft"]
  products: ["windows_server_2019", "windows_10"]
  severity_min: "HIGH"

- name: "VPN 设备"
  keywords: ["vpn", "firewall", "pulse_secure"]
  epss_min: 0.1 # 仅关注利用概率 > 10% 的漏洞
```

---

## 贡献与支持

我们热烈欢迎各种形式的贡献！TL-ICScan 是一个开源项目，依靠社区的力量不断改进。

### 如何贡献

- **提交 Issue**: 报告 bug、提出新功能建议或分享使用经验
- **提交 Pull Request**: 贡献代码、文档或测试用例
  - 请先阅读 [贡献指南](CONTRIBUTING.md) 了解开发规范
  - 确保代码通过所有测试并遵循项目风格
- **改进文档**: 帮助完善文档、添加示例或翻译
- **报告安全问题**: 负责任地披露安全漏洞，请参考 [安全政策](SECURITY.md)
- **Star 项目**: 如果觉得有用，请给我们一个 Star 支持项目发展！
- **分享反馈**: 在 Discussions 中分享您的使用场景和建议

### 贡献者

感谢所有为 TL-ICScan 做出贡献的开发者！

<!-- 贡献者列表将自动更新 -->

### 开源协议

本项目采用 MIT 开源协议，您可以自由地：
- 商业使用
- 修改源代码
- 分发副本
- 私人使用

唯一要求是保留原始许可证和版权声明。详见 [LICENSE](LICENSE)。

## 项目状态

- **开发状态**: 活跃维护中
- **稳定性**: 生产就绪
- **测试覆盖率**: 持续改进中
- **文档完整度**: 完善

## 致谢

感谢以下项目和组织提供的数据源：
- [NVD](https://nvd.nist.gov/) - National Vulnerability Database
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - Known Exploited Vulnerabilities
- [Exploit-DB](https://www.exploit-db.com/) - Exploit Database
- [EPSS](https://www.first.org/epss/) - Exploit Prediction Scoring System
- [Microsoft MSRC](https://msrc.microsoft.com/) - Microsoft Security Response Center

## Star 历史

[![Star History Chart](https://api.star-history.com/svg?repos=tianlusec/TL-ICScan&type=Date)](https://star-history.com/#tianlusec/TL-ICScan&Date)

## 联系我们

- **项目主页**: [GitHub Repository](https://github.com/tianlusec/TL-ICScan)
- **问题反馈**: [GitHub Issues](https://github.com/tianlusec/TL-ICScan/issues)
- **功能讨论**: [GitHub Discussions](https://github.com/tianlusec/TL-ICScan/discussions)
- **安全报告**: 请参考 [SECURITY.md](SECURITY.md)

## 许可证

本项目采用 [MIT License](LICENSE) 开源协议。

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

**由天禄实验室 (Tianlu Laboratory) 开发和开源维护**

*让漏洞情报触手可及 | Making Vulnerability Intelligence Accessible*
