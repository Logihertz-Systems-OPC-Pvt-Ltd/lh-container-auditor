# Contributing to lh-container-auditor

Thank you for your interest in contributing to `lh-container-auditor`, an enterprise open-source security tool developed by **Logihertz Systems (OPC) Private Limited**.

We welcome contributions from the security and developer community. Please read this guide before submitting issues or pull requests.

---

## Code of Conduct

All contributors and maintainers are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). Harassment, discrimination, or abusive behavior will not be tolerated.

---

## Development Environment Setup

This project uses [`uv`](https://github.com/astral-sh/uv) as its fast Python package and environment manager. Python 3.11 or newer is required.

### 1. Clone the Repository

```bash
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-container-auditor.git
cd lh-container-auditor
```

### 2. Set Up the Virtual Environment

```bash
# Create a virtual environment using uv
uv venv

# Activate the virtual environment
source .venv/bin/activate

# Install dependencies and editable package with development tools
uv pip install -e ".[dev]"
```

---

## Engineering Standards

To maintain security, reliability, and code quality across all Logihertz repositories, all contributions must comply with the following standards:

### 1. Python Standards
- **Python Version**: Pure Python 3.11+ standard library features and syntax.
- **Future Annotations**: Every Python module (`src/` and `tests/`) must start with:
  ```python
  from __future__ import annotations
  ```
- **Type Annotations**: All function signatures, method parameters, and return types must be fully type-annotated.
- **Line Length**: Maximum line length is strictly **100 characters** (`line-length = 100`).

### 2. Zero-Daemon & Offline Architecture
- `lh-container-auditor` must execute entirely offline without requiring background daemons, root privileges, or external network calls during analysis.
- Telemetry reporting, outbound HTTP tracking, or external key lookups are strictly prohibited.

---

## Verification & Testing

Before submitting a pull request, run the complete verification suite locally:

```bash
# 1. Code style and linting check with Ruff
uv run ruff check src/ tests/

# 2. Formatting verification with Ruff
uv run ruff format --check src/ tests/

# 3. Static application security testing (SAST) with Bandit
uv run bandit -r src/

# 4. Comprehensive test execution with Pytest
uv run pytest
```

All checks must pass with zero errors, zero warnings, and 100% test pass rate.

---

## Submitting Pull Requests

1. **Branch Naming**: Use descriptive branch names:
   - `feat/<feature-name>` for new features or detection rules
   - `fix/<bug-name>` for bug fixes or false-positive corrections
   - `docs/<doc-update>` for documentation improvements
2. **Commit Messages**: Follow Conventional Commits format:
   - `feat: add detection rule for ...`
   - `fix: resolve parser false positive on ...`
   - `docs: update CLI usage examples`
3. **Pull Request Checklist**: Fill out the [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md) completely, confirming that all linters, security scans, and tests pass.

---

## Questions & Contact

For questions, feedback, or operational support, reach out to the maintainers at **ops@logihertz.com**.
