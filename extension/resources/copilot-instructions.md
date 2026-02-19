# CodeTrust — Mandatory AI Governance Rules

> These rules are enforced by the CodeTrust VS Code extension.
> They apply to every session in every workspace without exception.
> All validated actions are logged to `.codetrust/audit.jsonl`.

---

## Proxy Enforcement Tools

CodeTrust exposes **proxy replacement tools** that MUST be called instead of the
native VS Code tools. The AI may only proceed with the native tool after receiving
`"status": "APPROVED"` from the corresponding proxy tool.

| Native Tool | Proxy Tool (call this first) |
|---|---|
| `run_in_terminal` | `codetrust_run_in_terminal` |
| `create_file` | `codetrust_create_file` |
| `replace_string_in_file` | `codetrust_replace_string_in_file` |
| `edit_notebook_file` | `codetrust_edit_notebook` |

---

## Mandatory Two-Step Workflow for Every Action

```
Step 1: Call codetrust_<tool>(same parameters as native tool)
Step 2: Read the response:
   status=APPROVED → call native tool with EXACT same parameters
   status=BLOCKED  → STOP. Do NOT proceed. Use the suggestion.
   status=WARN     → acknowledge the warning, then proceed.
```

**This workflow is non-negotiable. Zero exceptions.**

---

## Validation-Only Tools

For operations without a proxy equivalent, call the validate tool and check verdict:

| Operation | Validation Tool |
|---|---|
| Package installation | `codetrust_validate_package` |
| File deletion | `codetrust_validate_file_delete` |

---

## Absolute Prohibitions

| Action | Reason |
|--------|--------|
| `git push` | User MUST push manually. Never automate. |
| Heredoc (`<< EOF`) | Shell escaping corrupts files. Use `create_file`. |
| `eval` / `exec` | Dynamic code execution risk. |
| Hardcoded secrets, API keys | Use environment variables. |
| `from module import *` | Wildcard imports. Import explicitly. |
| `Any` type annotation | Use explicit types always. |
| Skipping validation | Zero exceptions. Always validate. |
| `print()` in production code | Use `structlog` or `logging`. |
| Bare `except:` | Always catch specific exception types. |
| Magic numbers inline | Extract to named constants. |

---

## Code Quality Requirements

Applied to all generated code without exception:

- **Type annotations** — every parameter and return type
- **Docstrings** — every public function and class
- **Short functions** — max ~40 lines, split by responsibility
- **Error handling** — every external call in try/except with specific types
- **No TODO/HACK/FIXME** — resolve before commit or open an issue
- **DRY** — if logic appears twice, extract it

---

## Enforcement

- Audit log: `.codetrust/audit.jsonl` — every action logged
- Status bar: CodeTrust extension shows live governance state
- All bypasses are detectable in the audit trail
- Run `CodeTrust: Governance Status` to verify injection state


---

## MANDATORY: Pre-Action Validation Protocol

### Before running ANY terminal command

1. Call `codetrust_validate_command` with the exact command you intend to run.
2. If verdict is `BLOCK` — **do NOT run the command**. Use the suggestion instead.
3. If verdict is `WARN` — acknowledge the warning explicitly before proceeding.
4. Only if verdict is `ALLOW` — call `run_in_terminal`.

```
codetrust_validate_command("npm install some-pkg")
→ ALLOW → you may call run_in_terminal
→ BLOCK → stop. use suggested alternative only.
```

### Before writing or editing ANY file

1. Call `codetrust_validate_file_write` with the path and content.
2. If verdict is `BLOCK` — **do NOT write the file**.
3. Only if verdict is `ALLOW` or `WARN` — call `create_file` or `replace_string_in_file`.

### Before installing ANY package

1. Call `codetrust_validate_package` with the package name and registry.
2. If verdict is `BLOCK` — **do NOT install the package**.
3. If verdict is `WARN` — tell the user and ask for explicit confirmation.

### Before deleting ANY file

1. Call `codetrust_validate_file_delete` with the path.
2. If verdict is `BLOCK` — **do NOT delete the file**.

---

## MANDATORY: Sequence for Every Work Session

Before writing any code at the start of a task:

1. Call `codetrust_governance_status` to confirm governance is active.
2. Use `codetrust_validate_command` before EVERY terminal command — no exceptions.
3. Use `codetrust_validate_file_write` before EVERY file write — no exceptions.

---

## Absolute Prohibitions (Never Do These)

| Action | Why |
|--------|-----|
| `git push` | User MUST push manually. Never automate. |
| Heredoc (`<< EOF`) | Corrupts files via shell escaping. Use `create_file` tool. |
| `eval()` / `exec()` | Remote code execution risk. |
| Hardcoded secrets, API keys, passwords | Use environment variables. |
| `from module import *` | Wildcard imports. Import explicitly. |
| Skipping validation "to save time" | Zero exceptions. Always validate. |
| Bare `except:` | Always catch specific exception types. |
| `print()` in production code | Use structured logging (`structlog`, `logging`). |
| `Any` type annotation | Use explicit types always. |
| Magic numbers inline | Extract to named constants. |

---

## Code Quality Requirements (Always Apply)

- Every function must have type annotations on all parameters and return type.
- Every public function and class must have a docstring.
- Every external call must be wrapped in try/except with specific exception types.
- Functions must be ≤40 lines. Split by responsibility if longer.
- No `TODO`, `HACK`, or `FIXME` in committed code.
- DRY: if similar logic appears twice, extract it.

---

## Enforcement

All gateway validations are logged to `.codetrust/audit.jsonl`.
Bypassed validations are detectable in the audit log.
Non-compliance is flagged in the CodeTrust status bar.
