# Contributing Guide

Thank you for your interest in TL-ICScan Vulnerability Intelligence Aggregation and Analysis Tool! We warmly welcome and appreciate every contribution from the community.

Whether you want to fix a small bug, add a new feature, improve documentation, or share your experience, we welcome it all!

[中文版](CONTRIBUTING.md)

## How to Start

1. **Fork this repository**: Click the Fork button in the top right corner.
2. **Clone to local**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/TL-ICScan.git
   ```
3. **Create a new branch**:
   ```bash
   git checkout -b feature/my-new-feature
   ```

## Development Environment Setup

### Prerequisites

- **Rust**: Version 1.70 or higher
- **Python**: Version 3.8 or higher
- **Git**: For version control

### Environment Configuration

1. **Install Rust Toolchain**
   ```bash
   # Visit https://rustup.rs/ to install rustup
   rustup update stable
   ```

2. **Install Python Dependencies**
   ```bash
   # Recommended to use virtual environment
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Build Rust Core**
   ```bash
   cd tianlu-intel-core
   cargo build --release
   cargo test  # Run tests
   ```

### Code Style

- **Rust**:
  - Use `cargo fmt` to format code
  - Use `cargo clippy` for code quality checks
  - Follow official Rust style guidelines

- **Python**:
  - Use `black` for code formatting (line length 88)
  - Use `flake8` for code linting
  - Use `mypy` for type checking
  - Follow PEP 8 conventions

- **Web UI**:
  - Developed using `streamlit`
  - Run `streamlit run web_ui/dashboard.py` to start development server
  - Keep code clean and readable

## Commit Conventions

We recommend using the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat: Add new Collector (CNNVD)`
- `fix: Fix null pointer exception during ingest`
- `docs: Update README installation steps`
- `chore: Upgrade dependency versions`

## Pull Request Process

### Pre-submission Checklist

Before submitting a PR, please ensure:

- [ ] Code passes all existing tests
- [ ] New features have corresponding test cases
- [ ] Code follows project style guidelines (run `cargo fmt` and `black`)
- [ ] Related documentation is updated (if necessary)
- [ ] Commit messages follow conventions (see below)
- [ ] PR description clearly explains changes and reasons

### Submission Steps

1. **Fork and Create Branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Develop and Commit**
   ```bash
   git add .
   git commit -m "feat: add new feature"
   git push origin feature/your-feature-name
   ```

3. **Create Pull Request**
   - Submit PR to `main` branch
   - Fill in PR template (if available)
   - Explain in description:
     - Purpose and background of changes
     - Implementation approach
     - Testing methods and results
     - Related Issue numbers (if any)

4. **Code Review**
   - Wait for maintainer review
   - Make modifications based on feedback
   - Keep PR updated and mergeable

5. **Merge**
   - After maintainer approval, your PR will be merged
   - Thank you for your contribution!

## Guide for Adding New Collectors

If you want to add a new intelligence source collector, please follow these steps:

### 1. Create Collector File

Create `source_name.py` under `tianlu_intel_collectors/tianlu_intel_collectors/`:

```python
"""
Source Name Collector
Collects vulnerability intelligence from [Data Source Name]
"""

import logging
from typing import List, Dict, Any
from .models import NormalizedCVE
from .config import get_config
from .errors import CollectorError

logger = logging.getLogger(__name__)

def collect_source_name() -> List[NormalizedCVE]:
    """
    Collect Source Name data
    
    Returns:
        List[NormalizedCVE]: Standardized CVE list
    """
    # Implement collection logic
    pass
```

### 2. Ensure Output Format

Output must comply with `NormalizedCVE` format (JSONL), one JSON object per line:

```json
{
  "cve_id": "CVE-2024-12345",
  "published": "2024-01-01T00:00:00Z",
  "severity": "HIGH",
  "description": "Vulnerability description",
  "vendors": ["vendor1"],
  "products": ["product1"],
  "references": ["https://example.com"],
  "sources": ["source_name"]
}
```

### 3. Add Tests

Add test file in `tests/` directory:

```python
def test_collect_source_name():
    """Test Source Name collector"""
    results = collect_source_name()
    assert len(results) > 0
    assert all(isinstance(r, NormalizedCVE) for r in results)
```

### 4. Update Documentation

- Add detailed docstrings in collector file
- Update data source list in README.md
- Update configuration documentation if special config is needed

### 5. Integrate into Update Scripts

Add invocation in `update_all.bat` and `update_all.sh`:

```bash
python -m tianlu_intel_collectors.source_name > data/source_name.jsonl
```

## Reporting Bugs

Found a bug? Please help us improve!

### Bug Reports Should Include

1. **Clear Title**: Concise description of the issue
2. **Environment Information**:
   - Operating system and version
   - Python version
   - Rust version
   - TL-ICScan version
3. **Reproduction Steps**: Detailed step-by-step instructions
4. **Expected Behavior**: What you expected to happen
5. **Actual Behavior**: What actually happened
6. **Error Logs**: Complete error messages and stack traces
7. **Screenshots**: If applicable

## Feature Suggestions

Have a great idea? We'd love to hear it!

### Feature Suggestions Should Include

1. **Use Case**: Describe your need scenario
2. **Proposed Solution**: How you think it should be implemented
3. **Alternatives**: Have you considered other approaches
4. **Priority**: How important is this feature to you

## Code of Conduct

### Our Pledge

To foster an open and welcoming environment, we pledge to:

- Respect differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community
- Show empathy towards other community members

### Unacceptable Behavior

- Use of sexualized language or imagery
- Personal attacks or insulting comments
- Public or private harassment
- Publishing others' private information without permission
- Other unethical or unprofessional conduct

## License

By contributing code, you agree that your contributions will be licensed under the MIT License.

## Questions?

If you have any questions:
- Check [README_EN.md](README_EN.md) and existing documentation
- Search existing Issues
- Ask in GitHub Discussions
- Contact maintainers via Issue

---

Thank you again for your contribution! Every contribution makes TL-ICScan better. 
