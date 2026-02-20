# Copyright (c) Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Signature Validator — detects AI-hallucinated function calls.

Catches what no other tool catches:
    1. Functions that don't exist in a module (e.g. requests.get_async)
    2. Wrong parameter names (e.g. using 'body' instead of 'data')
    3. Deprecated parameters (e.g. pd.read_csv(date_parser=...))
    4. Missing required arguments (e.g. calling get() without url)
    5. Known AI hallucination patterns (e.g. Flask(debug=True))

Architecture:
    - Uses regex-based import/call extraction (no AST dependency)
    - Validates against curated signature database (src/rules/signatures.py)
    - Works without packages installed — CI/CD friendly
    - Covers Python, JavaScript, TypeScript

This is what AI Hallucination Firewall does with Jedi (Python-only).
We do it better: multi-language, no installation required, AI-specific.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import structlog

from src.models.enums import Severity
from src.models.responses import Finding
from src.rules.signatures import (
    SIGNATURES,
    FunctionSig,
    ModuleSig,
)

logger = structlog.get_logger()

# ═══════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════

RULE_PREFIX = "sig"
MAX_FINDINGS_PER_FILE = 50
MAX_DISTANCE_SENTINEL = 999
MAX_PARAM_EDIT_DISTANCE = 2
MAX_FUNC_EDIT_DISTANCE = 3
HALLUCINATION_CONFIDENCE = 0.95
UNKNOWN_FUNC_CONFIDENCE = 0.7
MAX_SUGGESTIONS = 8

# Regex patterns for import resolution
_PY_IMPORT_RE = re.compile(
    r"^\s*import\s+(\w+)(?:\s+as\s+(\w+))?",
    re.MULTILINE,
)
_PY_FROM_IMPORT_RE = re.compile(
    r"^\s*from\s+([\w.]+)\s+import\s+(.+)",
    re.MULTILINE,
)
# Multi-line parenthesized: from module import (\n  a,\n  b\n)
_PY_FROM_IMPORT_PAREN_RE = re.compile(
    r"^\s*from\s+([\w.]+)\s+import\s*\(([^)]+)\)",
    re.MULTILINE | re.DOTALL,
)

_JS_IMPORT_RE = re.compile(
    r"""^\s*(?:import|const|let|var)\s+"""
    r"""(?:(\w+)|{([^}]+)})\s+"""
    r"""(?:=\s*require\s*\(|from\s+)"""
    r"""['"]([\w@/.:_-]+)['"]""",
    re.MULTILINE,
)

# JS/TS: import * as X from 'module'
_JS_STAR_IMPORT_RE = re.compile(
    r"""^\s*import\s+\*\s+as\s+(\w+)\s+from\s+['"]([\w@/.:_-]+)['"]""",
    re.MULTILINE,
)

# Function call extraction — module.function(args) or module.sub.function(args)
# Only matches the opening of the call; args are extracted depth-aware.
_CALL_OPEN_RE = re.compile(
    r"\b((?:\w+\.)*\w+)\.(\w+)\s*\(",
)

# Keyword argument extraction — name=value
_KWARG_RE = re.compile(
    r"(\w+)\s*=",
)


# ═══════════════════════════════════════════════════════════════════════
#  DATA TYPES
# ═══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ImportBinding:
    """Maps a local name to a module and optionally a specific symbol."""

    local_name: str
    module_name: str
    symbol: str = ""


@dataclass(frozen=True)
class FunctionCall:
    """A parsed function call site."""

    module_alias: str
    function_name: str
    line: int
    keyword_args: list[str] = field(default_factory=list)
    positional_count: int = 0
    submodule: str = ""


# ═══════════════════════════════════════════════════════════════════════
#  IMPORT RESOLUTION
# ═══════════════════════════════════════════════════════════════════════

def _resolve_python_imports(code: str) -> dict[str, ImportBinding]:
    """Extract Python import bindings from source code.

    Handles:
        import requests
        import numpy as np
        from flask import Flask, jsonify
        from django.shortcuts import render

    Skips commented-out import lines (starting with #).
    Merges bindings from both single-line and parenthesized imports.

    Returns:
        Dict mapping local name -> ImportBinding.
    """
    bindings: dict[str, ImportBinding] = {}

    for match in _PY_IMPORT_RE.finditer(code):
        # H2 fix: skip if the import line is a comment
        line_start = code.rfind("\n", 0, match.start()) + 1
        prefix = code[line_start:match.start()].lstrip()
        if prefix.startswith("#"):
            continue
        module = match.group(1)
        alias = match.group(2) or module
        bindings[alias] = ImportBinding(
            local_name=alias,
            module_name=module,
        )

    # Try parenthesized multi-line imports first (more specific)
    paren_modules: set[str] = set()
    for match in _PY_FROM_IMPORT_PAREN_RE.finditer(code):
        line_start = code.rfind("\n", 0, match.start()) + 1
        prefix = code[line_start:match.start()].lstrip()
        if prefix.startswith("#"):
            continue
        module = match.group(1)
        paren_modules.add(module)
        _parse_from_import_names(module, match.group(2), bindings)

    # Then single-line imports — merge into bindings (don't skip module)
    for match in _PY_FROM_IMPORT_RE.finditer(code):
        line_start = code.rfind("\n", 0, match.start()) + 1
        prefix = code[line_start:match.start()].lstrip()
        if prefix.startswith("#"):
            continue
        module = match.group(1)
        names_str = match.group(2).strip()
        if names_str.startswith("("):
            # Skip — already handled by paren regex above
            continue
        _parse_from_import_names(module, names_str, bindings)

    return bindings


def _parse_from_import_names(
    module: str,
    names_str: str,
    bindings: dict[str, ImportBinding],
) -> None:
    """Parse comma-separated import names into bindings.

    Handles 'Symbol', 'Symbol as Alias', and inline comments.
    """
    for part in names_str.split(","):
        part = part.strip()
        if not part or part.startswith("#"):
            continue
        # Strip inline comments
        if "#" in part:
            part = part[:part.index("#")].strip()
        if not part:
            continue
        as_match = re.match(r"(\w+)\s+as\s+(\w+)", part)
        if as_match:
            symbol = as_match.group(1)
            alias = as_match.group(2)
        else:
            symbol = part.split()[0]
            alias = symbol
        bindings[alias] = ImportBinding(
            local_name=alias,
            module_name=module,
            symbol=symbol,
        )


def _resolve_js_imports(code: str) -> dict[str, ImportBinding]:
    """Extract JavaScript/TypeScript import bindings.

    Handles default imports, named imports, require(),
    and star imports (import * as X from 'module').

    Returns:
        Dict mapping local name -> ImportBinding.
    """
    bindings: dict[str, ImportBinding] = {}

    for match in _JS_IMPORT_RE.finditer(code):
        default_name = match.group(1)
        named_imports = match.group(2)
        module = match.group(3)

        if default_name:
            bindings[default_name] = ImportBinding(
                local_name=default_name,
                module_name=module,
            )
        if named_imports:
            for part in named_imports.split(","):
                part = part.strip()
                if not part:
                    continue
                as_match = re.match(r"(\w+)\s+as\s+(\w+)", part)
                if as_match:
                    sym = as_match.group(1)
                    alias = as_match.group(2)
                else:
                    sym = part
                    alias = part
                bindings[alias] = ImportBinding(
                    local_name=alias,
                    module_name=module,
                    symbol=sym,
                )

    # Handle: import * as X from 'module'
    for match in _JS_STAR_IMPORT_RE.finditer(code):
        alias = match.group(1)
        module = match.group(2)
        bindings[alias] = ImportBinding(
            local_name=alias,
            module_name=module,
        )

    return bindings


def resolve_imports(
    code: str,
    language: str,
) -> dict[str, ImportBinding]:
    """Resolve imports based on language.

    Args:
        code: Source code string.
        language: Programming language identifier.

    Returns:
        Dict mapping local name -> ImportBinding.
    """
    if language == "python":
        return _resolve_python_imports(code)
    if language in ("javascript", "typescript"):
        return _resolve_js_imports(code)
    return {}


# ═══════════════════════════════════════════════════════════════════════
#  CALL SITE EXTRACTION
# ═══════════════════════════════════════════════════════════════════════

def _is_kwarg_token(token: str) -> bool:
    """Check if a token contains a keyword assignment (=) but not comparison operators."""
    # Find all = characters and check they're not part of ==, !=, >=, <=
    idx = 0
    while idx < len(token):
        pos = token.find("=", idx)
        if pos == -1:
            return False
        # Check it's not ==, !=, >=, <=
        if pos + 1 < len(token) and token[pos + 1] == "=":
            idx = pos + 2
            continue
        if pos > 0 and token[pos - 1] in "!><":
            idx = pos + 1
            continue
        return True
    return False


def _count_positional_args(args_str: str) -> int:
    """Count positional arguments in a call (before any kwargs)."""
    if not args_str.strip():
        return 0

    count = 0
    depth = 0
    current = ""
    for char in args_str:
        if char in "([{":
            depth += 1
            current += char
        elif char in ")]}":
            depth -= 1
            current += char
        elif char == "," and depth == 0:
            token = current.strip()
            if token and not _is_kwarg_token(token):
                count += 1
            current = ""
        else:
            current += char

    token = current.strip()
    if token and not _is_kwarg_token(token):
        count += 1

    return count


def _extract_kwargs(args_str: str) -> list[str]:
    """Extract keyword argument names from a call's argument string."""
    kwargs: list[str] = []
    depth = 0
    current = ""

    for char in args_str:
        if char in "([{":
            depth += 1
            current += char
        elif char in ")]}":
            depth -= 1
            current += char
        elif char == "," and depth == 0:
            _try_extract_kwarg(current, kwargs)
            current = ""
        else:
            current += char

    _try_extract_kwarg(current, kwargs)
    return kwargs


def _try_extract_kwarg(token: str, output: list[str]) -> None:
    """Try to extract a kwarg name from an argument token."""
    token = token.strip()
    match = re.match(r"(\w+)\s*=(?!=)", token)
    if match:
        output.append(match.group(1))


def extract_calls(
    code: str,
    known_modules: set[str],
) -> list[FunctionCall]:
    """Extract function call sites for known modules.

    Uses depth-aware argument extraction to handle nested parens.

    Args:
        code: Source code.
        known_modules: Set of module alias names to look for.

    Returns:
        List of FunctionCall instances.
    """
    calls: list[FunctionCall] = []
    lines = code.splitlines()

    for line_num, line in enumerate(lines, 1):
        # Skip comments
        stripped = line.lstrip()
        if stripped.startswith(("#", "//", "*", "/*")):
            continue

        for match in _CALL_OPEN_RE.finditer(line):
            chain = match.group(1)
            func_name = match.group(2)

            # For chained calls like os.path.join(), use the first
            # segment as the module alias if it's a known module.
            # Extract submodule from chain (e.g. "path" from "os.path").
            first_segment = chain.split(".")[0]
            submodule = ""
            if chain in known_modules:
                module_alias = chain
            elif first_segment in known_modules:
                module_alias = first_segment
                # Remaining chain segments form the submodule path
                remaining = chain[len(first_segment) + 1:]
                if remaining:
                    submodule = remaining
            else:
                continue

            # Extract args with depth-aware paren matching
            args_str = _extract_balanced_args(line, match.end() - 1)

            kwargs = _extract_kwargs(args_str)
            pos_count = _count_positional_args(args_str)

            calls.append(FunctionCall(
                module_alias=module_alias,
                function_name=func_name,
                line=line_num,
                keyword_args=kwargs,
                positional_count=pos_count,
                submodule=submodule,
            ))

    return calls


def _extract_balanced_args(line: str, open_paren_idx: int) -> str:
    """Extract arguments between balanced parentheses.

    Handles nested calls like f(a, g(b), c=d(e)).
    """
    depth = 0
    start = open_paren_idx + 1
    for idx in range(open_paren_idx, len(line)):
        ch = line[idx]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return line[start:idx]
    # Unbalanced — return what we have (multi-line call)
    return line[start:]


# ═══════════════════════════════════════════════════════════════════════
#  VALIDATION ENGINE
# ═══════════════════════════════════════════════════════════════════════

def _lookup_function(
    module_sig: ModuleSig,
    func_name: str,
    binding: ImportBinding,
    submodule: str = "",
) -> FunctionSig | None:
    """Look up a function in the module signature database.

    Handles both top-level and submodule lookups.

    Args:
        module_sig: Module signature database entry.
        func_name: Function name to look up.
        binding: Import binding for the call.
        submodule: Submodule chain (e.g. "path" for os.path.join).
    """
    # Direct function lookup
    if func_name in module_sig.functions:
        return module_sig.functions[func_name]

    # Targeted submodule lookup (e.g. os.path.join → submodule="path")
    if submodule and submodule in module_sig.submodules:
        sub_funcs = module_sig.submodules[submodule]
        if func_name in sub_funcs:
            return sub_funcs[func_name]

    # Check submodules (e.g. os.path.join → module=os, path accessed differently)
    # This handles cases like: from django.shortcuts import render
    if binding.symbol or submodule:
        for _sub_name, sub_funcs in module_sig.submodules.items():
            if func_name in sub_funcs:
                return sub_funcs[func_name]

    return None


def _validate_call(
    call: FunctionCall,
    func_sig: FunctionSig,
    module_name: str,
    filepath: str,
) -> list[Finding]:
    """Validate a single function call against its signature.

    Delegates to specialised checkers for deprecated functions,
    hallucinated kwargs, deprecated parameters, and argument counts.
    """
    findings: list[Finding] = []
    findings.extend(_check_deprecated_function(call, func_sig, module_name, filepath))
    findings.extend(_check_hallucinated_kwargs(call, func_sig, module_name, filepath))
    findings.extend(_check_deprecated_params(call, func_sig, filepath))
    findings.extend(_check_arg_count(call, func_sig, module_name, filepath))
    return findings


def _check_deprecated_function(
    call: FunctionCall,
    func_sig: FunctionSig,
    module_name: str,
    filepath: str,
) -> list[Finding]:
    """Flag deprecated function usage."""
    if not func_sig.deprecated:
        return []

    msg = f"'{module_name}.{func_sig.name}' is deprecated"
    if func_sig.deprecated_since:
        msg += f" since {func_sig.deprecated_since}"
    suggestion = ""
    if func_sig.replacement:
        suggestion = f"Use '{func_sig.replacement}' instead."
        msg += f". Use '{func_sig.replacement}' instead"
    return [Finding(
        rule_id=f"{RULE_PREFIX}_deprecated_function",
        severity=Severity.WARN,
        message=msg,
        file=filepath,
        line=call.line,
        suggestion=suggestion,
    )]


def _check_hallucinated_kwargs(
    call: FunctionCall,
    func_sig: FunctionSig,
    module_name: str,
    filepath: str,
) -> list[Finding]:
    """Detect hallucinated or unknown keyword arguments."""
    if not call.keyword_args or not func_sig.params:
        return []

    findings: list[Finding] = []
    valid_params = {p.name for p in func_sig.params}

    for kwarg in call.keyword_args:
        if kwarg in valid_params:
            continue

        sev = Severity.WARN
        if kwarg in func_sig.common_hallucinations:
            sev = Severity.BLOCK
            suggestion = (
                f"'{kwarg}' is a common AI hallucination for "
                f"'{module_name}.{func_sig.name}()'. "
                f"Valid parameters: {', '.join(sorted(valid_params))}"
            )
        else:
            closest = _find_closest_param(kwarg, valid_params)
            suggestion = (
                f"Did you mean '{closest}'?"
                if closest
                else f"Valid parameters: {', '.join(sorted(valid_params))}"
            )

        findings.append(Finding(
            rule_id=f"{RULE_PREFIX}_unknown_param",
            severity=sev,
            message=(
                f"Unknown parameter '{kwarg}' for "
                f"'{module_name}.{func_sig.name}()'"
            ),
            file=filepath,
            line=call.line,
            suggestion=suggestion,
        ))

    return findings


def _check_deprecated_params(
    call: FunctionCall,
    func_sig: FunctionSig,
    filepath: str,
) -> list[Finding]:
    """Flag usage of deprecated parameters."""
    if not call.keyword_args or not func_sig.params:
        return []

    findings: list[Finding] = []
    deprecated_params = {
        p.name: p for p in func_sig.params if p.deprecated
    }
    for kwarg in call.keyword_args:
        if kwarg not in deprecated_params:
            continue
        param = deprecated_params[kwarg]
        msg = f"Parameter '{kwarg}' is deprecated"
        if param.deprecated_since:
            msg += f" since {param.deprecated_since}"
        suggestion = ""
        if param.replacement:
            suggestion = f"Use '{param.replacement}' instead."
            msg += f". Use '{param.replacement}' instead"
        findings.append(Finding(
            rule_id=f"{RULE_PREFIX}_deprecated_param",
            severity=Severity.WARN,
            message=msg,
            file=filepath,
            line=call.line,
            suggestion=suggestion,
        ))

    return findings


def _check_arg_count(
    call: FunctionCall,
    func_sig: FunctionSig,
    module_name: str,
    filepath: str,
) -> list[Finding]:
    """Check positional argument count against min_args / max_args."""
    findings: list[Finding] = []

    if func_sig.min_args is not None and call.positional_count < func_sig.min_args:
        findings.append(Finding(
            rule_id=f"{RULE_PREFIX}_too_few_args",
            severity=Severity.WARN,
            message=(
                f"'{module_name}.{func_sig.name}()' requires at least "
                f"{func_sig.min_args} positional argument(s), "
                f"got {call.positional_count}"
            ),
            file=filepath,
            line=call.line,
            suggestion=(
                f"Check the function signature for "
                f"'{module_name}.{func_sig.name}()'."
            ),
        ))

    # max_args == -1 means unlimited (variadic / *args) — skip check
    if (
        func_sig.max_args is not None
        and func_sig.max_args >= 0
        and call.positional_count > func_sig.max_args
    ):
        findings.append(Finding(
            rule_id=f"{RULE_PREFIX}_too_many_args",
            severity=Severity.WARN,
            message=(
                f"'{module_name}.{func_sig.name}()' accepts at most "
                f"{func_sig.max_args} positional argument(s), "
                f"got {call.positional_count}"
            ),
            file=filepath,
            line=call.line,
            suggestion=(
                f"Check the function signature for "
                f"'{module_name}.{func_sig.name}()'."
            ),
        ))

    return findings


def _find_closest_param(name: str, valid: set[str]) -> str:
    """Find the closest valid parameter name using edit distance."""
    if not valid:
        return ""

    best_name = ""
    best_dist = MAX_DISTANCE_SENTINEL

    for candidate in valid:
        dist = _levenshtein(name.lower(), candidate.lower())
        if dist < best_dist and dist <= MAX_PARAM_EDIT_DISTANCE:
            best_dist = dist
            best_name = candidate

    return best_name


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)

    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))

    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


# ═══════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ═══════════════════════════════════════════════════════════════════════

def validate_signatures(
    code: str,
    language: str,
    filepath: str = "",
) -> list[Finding]:
    """Validate function signatures in source code.

    Scans code for function calls to known libraries and validates:
    - Function exists in the module
    - Parameters are valid (not hallucinated)
    - Deprecated functions/params are flagged
    - Common AI mistakes are caught

    Args:
        code: Source code string.
        language: Programming language (python, javascript, typescript).
        filepath: File path for Finding metadata.

    Returns:
        List of Finding objects for detected issues.
    """
    lang_key = language.lower()
    sig_db = SIGNATURES.get(lang_key)
    if not sig_db:
        return []

    bindings = resolve_imports(code, lang_key)
    if not bindings:
        return []

    known_aliases, alias_to_binding = _build_alias_map(bindings, sig_db)
    if not known_aliases:
        return []

    calls = extract_calls(code, known_aliases)
    findings = _validate_all_calls(calls, alias_to_binding, sig_db, filepath)

    logger.debug(
        "signature_validation_complete",
        file=filepath,
        language=lang_key,
        calls_checked=len(calls),
        findings=len(findings),
    )
    return findings


def _build_alias_map(
    bindings: dict[str, ImportBinding],
    sig_db: dict[str, ModuleSig],
) -> tuple[set[str], dict[str, ImportBinding]]:
    """Build mapping from local aliases to known library modules."""
    known_aliases: set[str] = set()
    alias_to_binding: dict[str, ImportBinding] = {}

    for alias, binding in bindings.items():
        if binding.module_name in sig_db:
            known_aliases.add(alias)
            alias_to_binding[alias] = binding
        parent = binding.module_name.split(".")[0]
        if parent in sig_db and alias not in known_aliases:
            known_aliases.add(alias)
            alias_to_binding[alias] = ImportBinding(
                local_name=alias,
                module_name=parent,
                symbol=binding.symbol,
            )

    return known_aliases, alias_to_binding


def _validate_all_calls(
    calls: list[FunctionCall],
    alias_to_binding: dict[str, ImportBinding],
    sig_db: dict[str, ModuleSig],
    filepath: str,
) -> list[Finding]:
    """Validate each extracted call against the signature database."""
    findings: list[Finding] = []

    for call in calls:
        if len(findings) >= MAX_FINDINGS_PER_FILE:
            break

        binding = alias_to_binding.get(call.module_alias)
        if not binding:
            continue

        module_sig = sig_db.get(binding.module_name)
        if not module_sig:
            continue

        func_sig = _lookup_function(
            module_sig, call.function_name, binding, call.submodule,
        )

        if func_sig is None:
            findings.extend(
                _handle_unknown_function(call, binding, module_sig, filepath)
            )
        else:
            findings.extend(
                _validate_call(call, func_sig, binding.module_name, filepath)
            )

    return findings


def _handle_unknown_function(
    call: FunctionCall,
    binding: ImportBinding,
    module_sig: ModuleSig,
    filepath: str,
) -> list[Finding]:
    """Handle a call to a function not found in the signature database."""
    is_hallucinated = (
        call.function_name in module_sig.common_hallucinated_functions
    )

    if is_hallucinated:
        available = sorted(module_sig.functions.keys())
        return [Finding(
            rule_id=f"{RULE_PREFIX}_hallucinated_function",
            severity=Severity.BLOCK,
            message=(
                f"'{binding.module_name}.{call.function_name}()' does not exist. "
                f"This is a known AI hallucination."
            ),
            file=filepath,
            line=call.line,
            suggestion=(
                f"Available functions: {', '.join(available[:MAX_SUGGESTIONS])}"
            ),
            confidence=HALLUCINATION_CONFIDENCE,
        )]

    closest = _find_closest_function(call.function_name, module_sig)
    if closest:
        return [Finding(
            rule_id=f"{RULE_PREFIX}_unknown_function",
            severity=Severity.WARN,
            message=(
                f"'{binding.module_name}.{call.function_name}()' "
                f"not found in signature database."
            ),
            file=filepath,
            line=call.line,
            suggestion=f"Did you mean '{closest}'?",
            confidence=UNKNOWN_FUNC_CONFIDENCE,
        )]

    # No close match found — still report as INFO so it's not silently dropped
    available = sorted(module_sig.functions.keys())
    return [Finding(
        rule_id=f"{RULE_PREFIX}_unknown_function",
        severity=Severity.INFO,
        message=(
            f"'{binding.module_name}.{call.function_name}()' "
            f"not found in signature database."
        ),
        file=filepath,
        line=call.line,
        suggestion=(
            f"Available functions: {', '.join(available[:MAX_SUGGESTIONS])}"
        ),
        confidence=UNKNOWN_FUNC_CONFIDENCE,
    )]


def _find_closest_function(
    name: str,
    module_sig: ModuleSig,
) -> str:
    """Find closest matching function name in module."""
    all_funcs = set(module_sig.functions.keys())
    for sub_funcs in module_sig.submodules.values():
        all_funcs.update(sub_funcs.keys())

    best = ""
    best_dist = MAX_DISTANCE_SENTINEL

    for candidate in all_funcs:
        dist = _levenshtein(name.lower(), candidate.lower())
        if dist < best_dist and dist <= MAX_FUNC_EDIT_DISTANCE:
            best_dist = dist
            best = candidate

    return best


def get_coverage_stats() -> dict[str, int]:
    """Return signature database coverage statistics.

    Returns:
        Dict with module_count, function_count, hallucination_count.
    """
    module_count = 0
    function_count = 0
    hallucination_count = 0

    for _lang, sigs in SIGNATURES.items():
        seen_modules: set[str] = set()
        for _alias, module_sig in sigs.items():
            if module_sig.name in seen_modules:
                continue
            seen_modules.add(module_sig.name)
            module_count += 1
            function_count += len(module_sig.functions)
            for sub_funcs in module_sig.submodules.values():
                function_count += len(sub_funcs)
            hallucination_count += len(
                module_sig.common_hallucinated_functions
            )
            for func in module_sig.functions.values():
                hallucination_count += len(func.common_hallucinations)

    return {
        "modules": module_count,
        "functions": function_count,
        "hallucination_patterns": hallucination_count,
    }
