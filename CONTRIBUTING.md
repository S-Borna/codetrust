# Contributing to CodeTrust

Thank you for your interest in contributing to CodeTrust! This guide will help
you get started.

## Contributor License Agreement (CLA)

**All contributors must sign the [CLA](CLA.md) before their first contribution
can be merged.** This ensures that intellectual property rights are properly
assigned and that CodeTrust can continue to be distributed under its
proprietary license.

To sign, include the following statement in your first pull request:

> I have read the CLA and I agree to its terms.

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
3. Website: <https://codetrust.ai>

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
def process_results(items: list[str], *, verbose: bool = False) -> list[dict[str, str]]:
    """Process scan results and return formatted output.

    Args:
        items: List of items to process.
        verbose: If True, include additional detail in output.

    Returns:
        List of processed results with metadata.
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

The codebase is organized into four main components:

- **Backend** — Python scanning engine, API, CLI, and MCP server
- **Extension** — VS Code extension (TypeScript)
- **Dashboard** — Next.js web dashboard
- **Action** — GitHub Action for CI/CD

Contributors with repository access can explore the source layout directly.

## Adding a New Rule

Detailed instructions for adding rules are available in the internal development guide. At a high level:

1. Add the rule definition in the backend scanning engine
2. Add the matching rule in the VS Code extension scanner
3. Add tests to maintain parity between backend and extension
4. Update rule counts across documentation

## License

CodeTrust is proprietary software. By contributing, you agree that your
contributions will be licensed under the same terms as the project.

## Questions?

- Website: <https://codetrust.ai>
- Email: <contact@codetrust.ai>
