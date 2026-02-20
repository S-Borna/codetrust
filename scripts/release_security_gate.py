# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Release security gate — automated pre-release IP/security checks.

Run: python scripts/release_security_gate.py
Exit code 0 = all gates pass, 1 = one or more gates FAIL.

This script enforces the IP & Security Gates defined in
docs/RELEASE_CHECKLIST.md. It MUST pass before every release.

Individual gate: python scripts/release_security_gate.py --check headers
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
EXT_SRC = ROOT / "extension" / "src"
EXT_OUT = ROOT / "extension" / "out"

# Gate result constants
PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"

# Secrets patterns to detect in source
SECRETS_PATTERNS: list[str] = [
    r"sk_live_[A-Za-z0-9]+",
    r"sk_test_[A-Za-z0-9]+",
    r"AKIA[A-Z0-9]{16}",
    r"ghp_[A-Za-z0-9]{36}",
    r"ghs_[A-Za-z0-9]{36}",
    r"password\s*=\s*['\"][^'\"]+['\"]",
    r"secret\s*=\s*['\"][^'\"]+['\"]",
    r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
]


def gate_s1_no_sdist() -> tuple[str, str]:
    """Gate S1: Verify pyproject.toml blocks sdist distribution."""
    pyproject = ROOT / "pyproject.toml"
    if not pyproject.exists():
        return FAIL, "pyproject.toml not found"

    text = pyproject.read_text()

    if '[tool.hatch.build.targets.sdist]' not in text:
        return FAIL, "Missing [tool.hatch.build.targets.sdist] section"

    if 'exclude = ["*"]' not in text:
        return FAIL, 'sdist section must have exclude = ["*"]'

    # Check dist/ for stale .tar.gz
    dist_dir = ROOT / "dist"
    if dist_dir.exists():
        tar_files = list(dist_dir.glob("*.tar.gz"))
        if tar_files:
            names = ", ".join(f.name for f in tar_files)
            return WARN, f"Stale .tar.gz in dist/: {names} — delete before publishing"

    return PASS, "sdist blocked in pyproject.toml"


def gate_s2_copyright_headers() -> tuple[str, str]:
    """Gate S2: Verify all source files have copyright headers."""
    issues: list[str] = []

    # Python files
    py_files = list(SRC.rglob("*.py"))
    for py_file in py_files:
        first_lines = py_file.read_text(errors="replace")[:200]
        if "Copyright (c)" not in first_lines and "Said Borna" not in first_lines:
            rel = py_file.relative_to(ROOT)
            issues.append(f"  Missing header: {rel}")

    # TypeScript files
    if EXT_SRC.exists():
        ts_files = list(EXT_SRC.rglob("*.ts"))
        for ts_file in ts_files:
            first_lines = ts_file.read_text(errors="replace")[:200]
            if "Copyright (c)" not in first_lines and "Said Borna" not in first_lines:
                rel = ts_file.relative_to(ROOT)
                issues.append(f"  Missing header: {rel}")

    if issues:
        detail = "\n".join(issues[:10])
        count = len(issues)
        return FAIL, f"{count} file(s) missing copyright header:\n{detail}"

    py_count = len(py_files)
    ts_count = len(list(EXT_SRC.rglob("*.ts"))) if EXT_SRC.exists() else 0
    return PASS, f"All {py_count} .py + {ts_count} .ts files have headers"


def gate_s3_source_maps_disabled() -> tuple[str, str]:
    """Gate S3: Verify TypeScript source maps are disabled."""
    tsconfig = ROOT / "extension" / "tsconfig.json"
    if not tsconfig.exists():
        return WARN, "extension/tsconfig.json not found"

    text = tsconfig.read_text()
    if '"sourceMap": true' in text or '"sourceMap":true' in text:
        return FAIL, "sourceMap is enabled in tsconfig.json"

    if '"sourceMap": false' not in text and '"sourceMap":false' not in text:
        return WARN, "sourceMap setting not found in tsconfig.json"

    # Check for .map files in output
    if EXT_OUT.exists():
        map_files = list(EXT_OUT.rglob("*.map"))
        if map_files:
            names = ", ".join(f.name for f in map_files)
            return FAIL, f"Source map files found in extension/out/: {names}"

    return PASS, "sourceMap disabled, no .map files"


def gate_s4_extension_minified() -> tuple[str, str]:
    """Gate S4: Verify extension output is bundled and minified."""
    pkg_json = ROOT / "extension" / "package.json"
    if not pkg_json.exists():
        return WARN, "extension/package.json not found"

    pkg = json.loads(pkg_json.read_text())
    scripts = pkg.get("scripts", {})

    prepublish = scripts.get("vscode:prepublish", "")
    if "bundle" not in prepublish:
        return FAIL, f"vscode:prepublish should run bundle, found: {prepublish}"

    if "bundle" not in scripts:
        return FAIL, "Missing 'bundle' script in package.json"

    dev_deps = pkg.get("devDependencies", {})
    if "esbuild" not in dev_deps:
        return FAIL, "esbuild not in devDependencies"

    # Check if extension output exists and is minified
    ext_js = EXT_OUT / "extension.js"
    if ext_js.exists():
        content = ext_js.read_text(errors="replace")
        line_count = content.count("\n") + 1
        if line_count > 200:
            return WARN, f"extension.js has {line_count} lines — may not be minified (run npm run bundle)"

    return PASS, "esbuild configured, bundle script in prepublish"


def gate_s5_license_validation() -> tuple[str, str]:
    """Gate S5: Verify license validation module is present and integrated."""
    issues: list[str] = []

    guard = SRC / "services" / "license_guard.py"
    if not guard.exists():
        return FAIL, "src/services/license_guard.py not found"

    # Check it compiles
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", str(guard)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return FAIL, f"license_guard.py compilation failed: {result.stderr}"

    # Check API integration
    api_py = SRC / "api.py"
    if api_py.exists():
        api_text = api_py.read_text()
        if "validate_license" not in api_text:
            issues.append("api.py missing validate_license integration")
        if "/v1/license/validate" not in api_text:
            issues.append("api.py missing /v1/license/validate endpoint")

    # Check config
    config_py = SRC / "config.py"
    if config_py.exists():
        config_text = config_py.read_text()
        if "license_key" not in config_text:
            issues.append("config.py missing license_key setting")

    if issues:
        return FAIL, "; ".join(issues)

    return PASS, "license_guard.py present, compiles, integrated in api.py"


def gate_s6_cla() -> tuple[str, str]:
    """Gate S6: Verify CLA is in place."""
    cla = ROOT / "CLA.md"
    contributing = ROOT / "CONTRIBUTING.md"

    if not cla.exists():
        return FAIL, "CLA.md not found"

    if not contributing.exists():
        return FAIL, "CONTRIBUTING.md not found"

    contrib_text = contributing.read_text()
    if "CLA" not in contrib_text and "Contributor License" not in contrib_text:
        return FAIL, "CONTRIBUTING.md does not reference CLA"

    return PASS, "CLA.md present, CONTRIBUTING.md references it"


def gate_s7_no_secrets() -> tuple[str, str]:
    """Gate S7: Verify no secrets or API keys in source code."""
    combined_pattern = "|".join(f"({p})" for p in SECRETS_PATTERNS)
    compiled = re.compile(combined_pattern, re.IGNORECASE)

    findings: list[str] = []

    # Scan Python source
    for py_file in SRC.rglob("*.py"):
        rel = py_file.relative_to(ROOT)
        # Skip test files and example files
        if "test_" in py_file.name or ".example" in py_file.name:
            continue
        text = py_file.read_text(errors="replace")
        for i, line in enumerate(text.splitlines(), 1):
            # Skip comments and docstrings containing example patterns
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith('"""'):
                continue
            if compiled.search(line):
                # Skip known false positives: empty assignments, config defaults
                if '= ""' in line or "= ''" in line:
                    continue
                findings.append(f"  {rel}:{i}: {stripped[:80]}")

    # Scan TypeScript source
    if EXT_SRC.exists():
        for ts_file in EXT_SRC.rglob("*.ts"):
            rel = ts_file.relative_to(ROOT)
            text = ts_file.read_text(errors="replace")
            for i, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("//") or stripped.startswith("/*"):
                    continue
                if compiled.search(line):
                    if '""' in line or "''" in line:
                        continue
                    findings.append(f"  {rel}:{i}: {stripped[:80]}")

    if findings:
        detail = "\n".join(findings[:10])
        return FAIL, f"{len(findings)} potential secret(s) found:\n{detail}"

    return PASS, "No secrets detected in source"


def gate_s8_production_mode() -> tuple[str, str]:
    """Gate S8: Verify production mode hard-fail is implemented."""
    api_file = SRC / "api.py"
    if not api_file.exists():
        return FAIL, "src/api.py not found"

    content = api_file.read_text()

    # Check that production_mode triggers sys.exit(1)
    if "production_mode" not in content:
        return FAIL, "production_mode check not found in api.py"

    if "sys.exit(1)" not in content:
        return FAIL, "sys.exit(1) not found — hard-fail not implemented"

    # Check config has the setting
    config_file = SRC / "config.py"
    if config_file.exists():
        config_content = config_file.read_text()
        if "production_mode" not in config_content:
            return FAIL, "production_mode not found in config.py"

    return PASS, "Production mode hard-fail enabled"


def gate_s9_server_side_rules() -> tuple[str, str]:
    """Gate S9: Verify server-side rule delivery is configured."""
    rule_delivery = SRC / "services" / "rule_delivery.py"
    if not rule_delivery.exists():
        return FAIL, "src/services/rule_delivery.py not found"

    content = rule_delivery.read_text()

    # Check free tier is defined
    if "FREE_TIER_RULE_IDS" not in content:
        return FAIL, "FREE_TIER_RULE_IDS not defined"

    # Check HMAC signing
    if "hmac" not in content.lower():
        return FAIL, "HMAC rule signing not implemented"

    # Check download endpoint exists
    api_file = SRC / "api.py"
    if api_file.exists():
        api_content = api_file.read_text()
        if "/v1/rules/download" not in api_content:
            return FAIL, "Rule download endpoint not found in api.py"

    # Check analyzer supports premium rules
    analyzer_file = SRC / "services" / "static_analyzer.py"
    if analyzer_file.exists():
        analyzer_content = analyzer_file.read_text()
        if "premium_rules" not in analyzer_content:
            return FAIL, "StaticAnalyzer does not accept premium_rules"

    return PASS, "Server-side rule delivery configured"


def run_all_gates() -> bool:
    """Run all security gates and print results."""
    gates = [
        ("S1: No sdist distribution", gate_s1_no_sdist),
        ("S2: Copyright headers", gate_s2_copyright_headers),
        ("S3: Source maps disabled", gate_s3_source_maps_disabled),
        ("S4: Extension minified", gate_s4_extension_minified),
        ("S5: License validation", gate_s5_license_validation),
        ("S6: CLA in place", gate_s6_cla),
        ("S7: No secrets in source", gate_s7_no_secrets),
        ("S8: Production mode hard-fail", gate_s8_production_mode),
        ("S9: Server-side rule delivery", gate_s9_server_side_rules),
    ]

    print("=" * 60)
    print("  CodeTrust Release Security Gates")
    print("=" * 60)
    print()

    all_pass = True
    results: list[tuple[str, str, str]] = []

    for name, gate_fn in gates:
        status, detail = gate_fn()
        results.append((name, status, detail))
        if status == FAIL:
            all_pass = False

    for name, status, detail in results:
        icon = {"PASS": "\u2705", "FAIL": "\u274c", "WARN": "\u26a0\ufe0f"}.get(status, "?")
        print(f"  {icon} {status}  {name}")
        if status != PASS:
            for line in detail.split("\n"):
                print(f"           {line}")
        print()

    print("=" * 60)
    if all_pass:
        print("  \u2705 ALL GATES PASSED — release may proceed")
    else:
        print("  \u274c RELEASE BLOCKED — fix FAIL items above")
    print("=" * 60)

    return all_pass


def run_single_gate(name: str) -> bool:
    """Run a single gate by keyword."""
    gate_map: dict[str, object] = {
        "sdist": gate_s1_no_sdist,
        "headers": gate_s2_copyright_headers,
        "sourcemaps": gate_s3_source_maps_disabled,
        "minified": gate_s4_extension_minified,
        "license": gate_s5_license_validation,
        "cla": gate_s6_cla,
        "secrets": gate_s7_no_secrets,
        "production": gate_s8_production_mode,
        "rules": gate_s9_server_side_rules,
    }

    gate_fn = gate_map.get(name)
    if gate_fn is None:
        print(f"Unknown gate: {name}")
        print(f"Available: {', '.join(gate_map.keys())}")
        return False

    status, detail = gate_fn()  # type: ignore[operator]
    icon = {"PASS": "\u2705", "FAIL": "\u274c", "WARN": "\u26a0\ufe0f"}.get(status, "?")
    print(f"{icon} {status}  {detail}")
    return status != FAIL


def main() -> None:
    """Entry point for release security gate checks."""
    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        if len(sys.argv) < 3:
            print("Usage: release_security_gate.py --check <gate_name>")
            sys.exit(1)
        success = run_single_gate(sys.argv[2])
        sys.exit(0 if success else 1)

    success = run_all_gates()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
