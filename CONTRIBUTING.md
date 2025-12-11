# 贡献指南 (Contributing Guide)

感谢您对 TL-ICScan 漏洞情报聚合与分析工具的关注！我们非常欢迎并感激社区的每一份贡献。

无论您是想修复一个小 bug、添加新功能、改进文档，还是分享使用经验，我们都热烈欢迎！

[English Version](CONTRIBUTING_EN.md)

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

### 前置要求

- **Rust**: 1.70 或更高版本
- **Python**: 3.8 或更高版本
- **Git**: 用于版本控制

### 环境配置

1. **安装 Rust 工具链**
   ```bash
   # 访问 https://rustup.rs/ 安装 rustup
   rustup update stable
   ```

2. **安装 Python 依赖**
   ```bash
   # 建议使用虚拟环境
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **编译 Rust 核心**
   ```bash
   cd tianlu-intel-core
   cargo build --release
   cargo test  # 运行测试
   ```

### 代码风格

- **Rust**:
  - 使用 `cargo fmt` 格式化代码
  - 使用 `cargo clippy` 检查代码质量
  - 遵循 Rust 官方风格指南

- **Python**:
  - 使用 `black` 格式化代码（行长度 88）
  - 使用 `flake8` 进行代码检查
  - 使用 `mypy` 进行类型检查
  - 遵循 PEP 8 规范

- **Web UI**:
  - 使用 `streamlit` 开发
  - 运行 `streamlit run web_ui/dashboard.py` 启动开发服务器
  - 保持代码简洁和可读性

## 提交规范

我们推荐使用 [Conventional Commits](https://www.conventionalcommits.org/) 规范：

- `feat: 增加新的 Collector (CNNVD)`
- `fix: 修复 ingest 时的空指针异常`
- `docs: 更新 README 安装步骤`
- `chore: 升级依赖版本`

## Pull Request 流程

### 提交前检查清单

在提交 PR 之前，请确保：

- [ ] 代码已通过所有现有测试
- [ ] 新功能已添加相应的测试用例
- [ ] 代码符合项目风格规范（运行 `cargo fmt` 和 `black`）
- [ ] 更新了相关文档（如有必要）
- [ ] Commit 消息遵循规范（见下文）
- [ ] PR 描述清晰说明了变更内容和原因

### 提交步骤

1. **Fork 并创建分支**
   ```bash
   git checkout -b feature/your-feature-name
   # 或
   git checkout -b fix/your-bug-fix
   ```

2. **进行开发并提交**
   ```bash
   git add .
   git commit -m "feat: add new feature"
   git push origin feature/your-feature-name
   ```

3. **创建 Pull Request**
   - 提交 PR 到 `main` 分支
   - 填写 PR 模板（如有）
   - 在描述中详细说明：
     - 变更的目的和背景
     - 实现方法
     - 测试方法和结果
     - 相关的 Issue 编号（如有）

4. **代码审查**
   - 等待维护者 Review
   - 根据反馈进行修改
   - 保持 PR 更新和可合并状态

5. **合并**
   - 维护者批准后将合并您的 PR
   - 感谢您的贡献！

## 新增 Collector 指南

如果您想添加新的情报源采集器，请遵循以下步骤：

### 1. 创建采集器文件

在 `tianlu_intel_collectors/tianlu_intel_collectors/` 下新建 `source_name.py`：

```python
"""
Source Name Collector
采集 [数据源名称] 的漏洞情报
"""

import logging
from typing import List, Dict, Any
from .models import NormalizedCVE
from .config import get_config
from .errors import CollectorError

logger = logging.getLogger(__name__)

def collect_source_name() -> List[NormalizedCVE]:
    """
    采集 Source Name 数据
    
    Returns:
        List[NormalizedCVE]: 标准化的 CVE 列表
    """
    # 实现采集逻辑
    pass
```

### 2. 确保输出格式

输出必须符合 `NormalizedCVE` 格式（JSONL），每行一个 JSON 对象：

```json
{
  "cve_id": "CVE-2024-12345",
  "published": "2024-01-01T00:00:00Z",
  "severity": "HIGH",
  "description": "漏洞描述",
  "vendors": ["vendor1"],
  "products": ["product1"],
  "references": ["https://example.com"],
  "sources": ["source_name"]
}
```

### 3. 添加测试

在 `tests/` 目录下添加测试文件：

```python
def test_collect_source_name():
    """测试 Source Name 采集器"""
    results = collect_source_name()
    assert len(results) > 0
    assert all(isinstance(r, NormalizedCVE) for r in results)
```

### 4. 更新文档

- 在采集器文件中添加详细的文档字符串
- 更新 README.md 中的数据源列表
- 如有特殊配置需求，更新配置文档

### 5. 集成到更新脚本

在 `update_all.bat` 和 `update_all.sh` 中添加调用：

```bash
python -m tianlu_intel_collectors.source_name > data/source_name.jsonl
```

## 报告 Bug

发现 bug？请帮助我们改进！

### Bug 报告应包含

1. **清晰的标题**: 简洁描述问题
2. **环境信息**:
   - 操作系统和版本
   - Python 版本
   - Rust 版本
   - TL-ICScan 版本
3. **重现步骤**: 详细的步骤说明
4. **期望行为**: 您期望发生什么
5. **实际行为**: 实际发生了什么
6. **错误日志**: 完整的错误信息和堆栈跟踪
7. **截图**: 如果适用

## 功能建议

有好的想法？我们很乐意听取！

### 功能建议应包含

1. **使用场景**: 描述您的需求场景
2. **建议方案**: 您认为应该如何实现
3. **替代方案**: 是否考虑过其他方案
4. **优先级**: 这个功能对您有多重要

## 行为准则

### 我们的承诺

为了营造一个开放和友好的环境，我们承诺：

- 尊重不同的观点和经验
- 优雅地接受建设性批评
- 关注对社区最有利的事情
- 对其他社区成员表示同理心

### 不可接受的行为

- 使用性化的语言或图像
- 人身攻击或侮辱性评论
- 公开或私下骚扰
- 未经许可发布他人的私人信息
- 其他不道德或不专业的行为

## 许可证

通过贡献代码，您同意您的贡献将在 MIT 许可证下授权。

## 问题？

如有任何问题，请：
- 查看 [README.md](README.md) 和现有文档
- 搜索现有的 Issues
- 在 GitHub Discussions 中提问
- 通过 Issue 联系维护者

---

再次感谢您的贡献！每一份贡献都让 TL-ICScan 变得更好。
