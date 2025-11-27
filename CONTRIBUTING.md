# Contributing to TL-ICScan 漏洞情报聚合与分析工具

感谢您对 TL-ICScan 漏洞情报聚合与分析工具的关注！我们非常欢迎社区贡献。

## 如何开始

1. **Fork 本仓库**：点击右上角的 Fork 按钮。
2. **Clone 到本地**：
   ```bash
   git clone https://github.com/YOUR_USERNAME/TL-ICScan.git
   ```
3. **创建新分支**：
   ```bash
   git checkout -b feature/my-new-feature
   ```

## 开发环境设置

请参考 `README.md` 中的“快速开始”部分安装 Rust 和 Python 环境。

- **Rust**: 使用 `cargo fmt` 和 `cargo clippy` 确保代码风格。
- **Python**: 使用 `black` 或 `flake8` 保持代码整洁。
- **Web UI**: 使用 `streamlit` 开发。运行 `streamlit run web_ui/dashboard.py` 启动开发服务器。

## 提交规范

我们推荐使用 [Conventional Commits](https://www.conventionalcommits.org/) 规范：

- `feat: 增加新的 Collector (CNNVD)`
- `fix: 修复 ingest 时的空指针异常`
- `docs: 更新 README 安装步骤`
- `chore: 升级依赖版本`

## Pull Request 流程

1. 确保所有测试通过（如有）。
2. 提交 PR 到 `main` 分支。
3. 在 PR 描述中详细说明变更内容和测试方法。
4. 等待维护者 Review。

## 新增 Collector 指南

如果您想添加新的情报源：
1. 在 `tianlu_intel_collectors/tianlu_intel_collectors/` 下新建 `source_name.py`。
2. 确保输出格式符合 `NormalizedCVE` (JSONL)。
3. 在 `update_all` 脚本中添加调用示例。

感谢您的贡献！
