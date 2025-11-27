# Contributing to TL-ICScan Vulnerability Intelligence Aggregation and Analysis Tool

Thank you for your interest in TL-ICScan! We welcome community contributions.

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

Please refer to the "Quick Start" section in `README.md` to set up your Rust and Python environments.

- **Rust**: Use `cargo fmt` and `cargo clippy` to ensure code style consistency.
- **Python**: Use `black` or `flake8` to maintain code cleanliness.
- **Web UI**: Developed using `streamlit`. Run `streamlit run web_ui/dashboard.py` to start the development server.

## Commit Conventions

We recommend using the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat: Add new Collector (CNNVD)`
- `fix: Fix null pointer exception during ingest`
- `docs: Update README installation steps`
- `chore: Upgrade dependency versions`

## Pull Request Process

1. Ensure all tests pass (if applicable).
2. Submit your PR to the `main` branch.
3. Provide a detailed description of changes and testing methods in the PR description.
4. Wait for a maintainer to review your changes.

## Guide for Adding New Collectors

If you wish to add a new intelligence source:
1. Create a new file `source_name.py` under `tianlu_intel_collectors/tianlu_intel_collectors/`.
2. Ensure the output format complies with the `NormalizedCVE` (JSONL) schema.
3. Add an example invocation in the `update_all` script.

Thank you for your contribution!
