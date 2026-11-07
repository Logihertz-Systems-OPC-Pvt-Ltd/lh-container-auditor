## Description

Please provide a concise description of the changes introduced in this pull request.

---

## Type of Change

- [ ] New detection rule or security policy check
- [ ] Parser enhancement or new format support
- [ ] Bug fix or false-positive remediation
- [ ] Performance optimization or refactor
- [ ] Documentation update

---

## Quality & Security Checklist

Before requesting review, ensure all checks pass:

- [ ] Every Python source file includes `from __future__ import annotations`.
- [ ] Line lengths conform strictly to the **100-character limit** (`line-length = 100`).
- [ ] Full static linting passes: `uv run ruff check src/ tests/` (zero errors).
- [ ] Code formatting check passes: `uv run ruff format --check src/ tests/`.
- [ ] Security static analysis passes: `uv run bandit -r src/` (zero issues).
- [ ] Complete test suite passes: `uv run pytest` (100% pass rate).
- [ ] Tests have been added or updated covering the new logic.
- [ ] Documentation in `docs/` updated if new rules, CLI options, or formats were added.
