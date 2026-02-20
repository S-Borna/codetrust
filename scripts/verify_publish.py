# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Post-publish verification — validates published wheel on PyPI.

Run after every PyPI publish to verify the uploaded artifact is correct.
Prevents the v2.6.0 incident (empty wheel) from ever recurring.

Usage:
    python scripts/verify_publish.py [--version 2.6.1]
    python scripts/verify_publish.py  # auto-detects from pyproject.toml
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

# --- Constants ---

PACKAGE_NAME: str = "codetrust"
MIN_PYTHON_FILES: int = 50
MIN_WHEEL_SIZE_KB: int = 200
REQUIRED_ENTRY_POINTS: list[str] = [
    "src/cli.py",
    "src/server.py",
    "src/api.py",
    "src/config.py",
]
REQUIRED_DIRECTORIES: list[str] = [
    "src/",
    "src/services/",
    "src/rules/",
    "src/models/",
    "src/gateway/",
]


def _get_version_from_pyproject() -> str:
    """Extract version from pyproject.toml."""
    pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
    if not pyproject_path.exists():
        sys.stderr.write("ERROR: pyproject.toml not found\n")
        sys.exit(1)

    import tomllib

    with open(pyproject_path, "rb") as fh:
        data = tomllib.load(fh)
    return str(data["project"]["version"])


def _download_wheel(version: str, dest_dir: str) -> Path | None:
    """Download wheel from PyPI into dest_dir."""
    result = subprocess.run(
        [
            sys.executable, "-m", "pip", "download",
            f"{PACKAGE_NAME}=={version}",
            "--no-deps",
            "--no-cache-dir",
            "--only-binary=:all:",
            "-d", dest_dir,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )

    if result.returncode != 0:
        sys.stderr.write(f"ERROR: pip download failed:\n{result.stderr}\n")
        return None

    whl_files = list(Path(dest_dir).glob("*.whl"))
    if not whl_files:
        sys.stderr.write("ERROR: No .whl file downloaded\n")
        return None

    return whl_files[0]


def _verify_wheel(whl_path: Path) -> list[str]:
    """Verify wheel contents meet all quality gates. Returns list of errors."""
    errors: list[str] = []

    # Check file size
    size_kb = whl_path.stat().st_size / 1024
    if size_kb < MIN_WHEEL_SIZE_KB:
        errors.append(
            f"FAIL: Wheel size {size_kb:.0f} KB < minimum {MIN_WHEEL_SIZE_KB} KB"
        )

    with zipfile.ZipFile(whl_path, "r") as zf:
        all_files = zf.namelist()
        py_files = [f for f in all_files if f.endswith(".py")]
        total_count = len(all_files)
        py_count = len(py_files)

        # Check Python file count
        if py_count < MIN_PYTHON_FILES:
            errors.append(
                f"FAIL: Only {py_count} Python files (minimum: {MIN_PYTHON_FILES})"
            )

        # Check required entry points
        for entry in REQUIRED_ENTRY_POINTS:
            if entry not in py_files:
                errors.append(f"FAIL: Missing required file: {entry}")

        # Check required directories
        for req_dir in REQUIRED_DIRECTORIES:
            has_dir = any(f.startswith(req_dir) for f in all_files)
            if not has_dir:
                errors.append(f"FAIL: Missing required directory: {req_dir}")

        # Check for integrity markers (distribution verification)
        rules_file = "src/rules/anti_patterns.py"
        if rules_file in py_files:
            with zf.open(rules_file) as rf:
                rules_content = rf.read().decode("utf-8")
                marker_ids = [
                    "ct_sig_borna_2026_alpha",
                    "ct_sig_governance_w7x9",
                    "ct_sig_drift_k3m2_sentinel",
                ]
                for marker_id in marker_ids:
                    if marker_id not in rules_content:
                        errors.append(
                            f"FAIL: Integrity marker '{marker_id}' missing from rules"
                        )
        else:
            errors.append(f"FAIL: Rules file '{rules_file}' not found in wheel")

        # Print summary
        print(f"\n{'='*60}")
        print(f"WHEEL VERIFICATION: {whl_path.name}")
        print(f"{'='*60}")
        print(f"  Size:         {size_kb:.0f} KB")
        print(f"  Total files:  {total_count}")
        print(f"  Python files: {py_count}")
        print(f"  Entry points: {', '.join(REQUIRED_ENTRY_POINTS)}")

    return errors


def _verify_local_build() -> list[str]:
    """Verify the local dist/ wheel matches expectations."""
    dist_dir = Path(__file__).parent.parent / "dist"
    whl_files = list(dist_dir.glob("*.whl"))

    if not whl_files:
        return ["FAIL: No local wheel found in dist/. Run: python -m build --wheel"]

    return _verify_wheel(whl_files[0])


def main() -> int:
    """Main entry point for post-publish verification."""
    version = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else None

    if not version:
        for i, arg in enumerate(sys.argv):
            if arg == "--version" and i + 1 < len(sys.argv):
                version = sys.argv[i + 1]
                break

    if not version:
        version = _get_version_from_pyproject()

    print(f"\n  Verifying {PACKAGE_NAME}=={version} on PyPI...\n")

    # Step 1: Verify local build
    print("[1/2] Checking local dist/ wheel...")
    local_errors = _verify_local_build()
    if local_errors:
        for err in local_errors:
            print(f"  {err}")
        print("\n  Local wheel has issues. Fix before publishing.\n")
        return 1
    print("  OK — local wheel passes all checks\n")

    # Step 2: Download and verify PyPI wheel
    print(f"[2/2] Downloading {PACKAGE_NAME}=={version} from PyPI...")
    with tempfile.TemporaryDirectory() as tmpdir:
        whl_path = _download_wheel(version, tmpdir)
        if not whl_path:
            print("\n  ERROR: Could not download wheel from PyPI.\n")
            print("  If just published, wait 1-2 minutes for PyPI index to update.\n")
            return 1

        pypi_errors = _verify_wheel(whl_path)

        if pypi_errors:
            print(f"\n  {'='*60}")
            print(f"  VERIFICATION FAILED — {len(pypi_errors)} error(s):")
            print(f"  {'='*60}")
            for err in pypi_errors:
                print(f"    {err}")
            print("\n  ACTION: Do NOT announce this release. Fix and re-publish.\n")
            return 1

        # Compare sizes
        local_whl = list((Path(__file__).parent.parent / "dist").glob("*.whl"))
        if local_whl:
            local_size = local_whl[0].stat().st_size
            pypi_size = whl_path.stat().st_size
            size_diff_pct = abs(local_size - pypi_size) / max(local_size, 1) * 100
            if size_diff_pct > 5:
                print(
                    f"\n  WARNING: Size mismatch — local={local_size}B, "
                    f"PyPI={pypi_size}B ({size_diff_pct:.1f}% diff)\n"
                )
                return 1

    print(f"\n  {'='*60}")
    print("  VERIFICATION PASSED")
    print(f"  {PACKAGE_NAME}=={version} is correctly published on PyPI")
    print(f"  {'='*60}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
