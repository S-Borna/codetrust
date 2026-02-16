# Contributing to CodeTrust

Thank you for your interest in contributing to CodeTrust! This guide will help
you get started.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and
inclusive environment. Be kind, constructive, and professional in all
interactions.

## Getting Started

### Prerequisites

- Python 3.12+
- Node.js 20+ (for the VS Code extension)
- Git

### Development Setup

```bash
# Clone the repository (private)
# Request access via the website, then clone using your internal remote URL
cd codetrust

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run linter
ruff check src/ tests/
```

### Extension Development

```bash
cd extension
npm install
npm run compile
# Press F5 in VS Code to launch Extension Development Host
```

## How to Contribute

### Reporting Bugs

1. Report issues privately (the repository is not public)
2. Include: Python version, OS, steps to reproduce, expected vs actual behavior
3. Website: <https://codetrust.saidborna.com>

### Suggesting Features

1. Send feature requests privately (the repository is not public)
2. Describe the use case, not just the solution
3. Be specific about which component (CLI, API, Extension, Gateway)

### Submitting Code

1. **Fork** the repository
2. **Branch** from `main`: `git checkout -b feature/your-feature`
3. **Make changes** — follow the style guide below
4. **Add tests** — all new features require tests
5. **Run checks:**

   ```bash
   ruff check src/ tests/
   pytest tests/ -v
   ```

6. **Commit** with a clear message (see Commit Messages below)
7. **Push** and open a **Pull Request**

## Style Guide

### Python

- **Formatter:** ruff (line length 100)
- **Linter:** ruff with rules: E, W, F, I, N, UP, B, SIM, TCH, RUF
- **Types:** Use type hints for all function signatures
- **Docstrings:** Google style for public functions

```python
def scan_file(path: str, *, language: str | None = None) -> list[Finding]:
    """Scan a file for anti-patterns.

    Args:
        path: Absolute path to the file.
        language: Override language detection. If None, detected from extension.

    Returns:
        List of findings sorted by severity.
    """
```

### TypeScript (Extension)

- **Compiler:** tsc with strict mode
- **Style:** Follow existing patterns in `extension/src/`

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add Kubernetes pod security rules
fix: handle empty file in AST analyzer
docs: update CLI usage examples
test: add coverage for SARIF formatter
chore: bump tree-sitter to 0.24.0
```

## Project Structure

```
src/                    # Python backend
├── api.py              # FastAPI REST API
├── cli.py              # CLI entry point
├── server.py           # MCP server
├── gateway/            # AI Governance Gateway
│   ├── interceptor.py  # Command/content interception
│   ├── policies.py     # Policy engine (TOML config)
│   ├── audit.py        # JSONL audit logger
│   └── server.py       # MCP gateway server
├── rules/              # Anti-pattern rule definitions
├── services/           # Business logic
├── models/             # Pydantic request/response models
├── formatters/         # Output formatters (SARIF, etc.)
└── middleware/          # API middleware

extension/              # VS Code extension (TypeScript)
dashboard/              # Next.js web dashboard
action/                 # GitHub Action
tests/                  # Python test suite
```

## Adding a New Rule

1. Add the rule to `src/rules/anti_patterns.py`
2. Add the matching TypeScript rule to `extension/src/embedded-scanner.ts`
3. Add tests in `tests/test_parity.py`
4. Update rule counts in README.md, extension/README.md, and CHANGELOG.md

## License

CodeTrust is proprietary software. By contributing, you agree that your
contributions will be licensed under the same terms as the project.

## Questions?

- Website: <https://codetrust.saidborna.com>
- Email: <codetrust@saidborna.com>
