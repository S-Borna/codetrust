# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Compile Python source to native extensions via Cython.

Produces .so (Linux/macOS) or .pyd (Windows) files that replace readable .py
source in the distributed wheel. This is the primary technical barrier against
source code extraction.

Usage:
    python scripts/build_compiled.py          # compile src/ → build/compiled/
    python scripts/build_compiled.py --wheel   # compile + repackage into wheel

Requirements:
    pip install cython setuptools

How it works:
    1. Copies src/ to a staging directory
    2. Generates a Cython setup.py that compiles every .py → .so/.pyd
    3. Builds the compiled extensions
    4. Creates a wheel containing ONLY compiled files + __init__.py stubs
    5. Removes all readable .py from the output

Files that are NOT compiled (must remain as .py):
    - __init__.py (required for Python package discovery)
    - __main__.py (entry points)
    - templates/* (Jinja/text templates, not code)
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# --- Constants ---

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
SRC_DIR: Path = PROJECT_ROOT / "src"
BUILD_DIR: Path = PROJECT_ROOT / "build" / "compiled"
DIST_DIR: Path = PROJECT_ROOT / "dist"

# Files that must remain as readable .py (not compiled)
SKIP_COMPILE: set[str] = {
    "__init__.py",
    "__main__.py",
    "conftest.py",
}

# Directories whose contents are not code (templates, data)
SKIP_DIRS: set[str] = {
    "templates",
    "__pycache__",
}

EXTENSION_SUFFIX: str = ".pyd" if platform.system() == "Windows" else ".so"


def _find_compilable_modules(src_dir: Path) -> list[Path]:
    """Find all .py files eligible for Cython compilation."""
    modules: list[Path] = []
    for py_file in src_dir.rglob("*.py"):
        # Skip non-compilable files
        if py_file.name in SKIP_COMPILE:
            continue

        # Skip template/data directories
        relative = py_file.relative_to(src_dir)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue

        modules.append(py_file)

    return sorted(modules)


def _generate_setup_py(staging_dir: Path, modules: list[Path]) -> Path:
    """Generate a temporary setup.py for Cython compilation."""
    ext_modules_lines: list[str] = []
    for mod in modules:
        relative = mod.relative_to(staging_dir / "src")
        # Convert path to dotted module name: src/services/cache.py → src.services.cache
        module_name = "src." + str(relative.with_suffix("")).replace(os.sep, ".")
        ext_modules_lines.append(
            f'    Extension("{module_name}", ["{mod}"]),'
        )

    ext_list = "\n".join(ext_modules_lines)

    setup_content = f'''\
"""Auto-generated Cython build script. Do not edit."""
from setuptools import setup
from Cython.Build import cythonize
from setuptools import Extension

extensions = [
{ext_list}
]

setup(
    name="codetrust-compiled",
    ext_modules=cythonize(
        extensions,
        compiler_directives={{
            "language_level": "3",
            "boundscheck": False,
            "wraparound": False,
        }},
        nthreads=4,
    ),
)
'''
    setup_path = staging_dir / "setup_cython.py"
    setup_path.write_text(setup_content)
    return setup_path


def _create_init_stubs(build_output: Path, src_dir: Path) -> None:
    """Create minimal __init__.py stubs in the compiled output.

    These are required for Python to recognize directories as packages.
    They contain only the copyright header and docstring — no logic.
    """
    for init_file in src_dir.rglob("__init__.py"):
        relative = init_file.relative_to(src_dir)
        target = build_output / relative
        target.parent.mkdir(parents=True, exist_ok=True)

        # Read original docstring
        original = init_file.read_text()
        lines = original.splitlines()
        stub_lines: list[str] = [
            "# Copyright (c) 2026 Said Borna. All rights reserved.",
            "# Proprietary — see LICENSE for terms.",
        ]
        # Keep docstring if present
        in_docstring = False
        for line in lines:
            if '"""' in line and not in_docstring:
                in_docstring = True
                stub_lines.append(line)
                if line.count('"""') >= 2:
                    in_docstring = False
                continue
            if in_docstring:
                stub_lines.append(line)
                if '"""' in line:
                    in_docstring = False
                continue

        target.write_text("\n".join(stub_lines) + "\n")


def _copy_non_code_files(build_output: Path, src_dir: Path) -> None:
    """Copy template files and other non-code resources."""
    for skip_dir in SKIP_DIRS:
        if skip_dir == "__pycache__":
            continue
        template_src = src_dir / skip_dir
        if template_src.exists():
            template_dst = build_output / skip_dir
            shutil.copytree(template_src, template_dst, dirs_exist_ok=True)

    # Also copy from subdirectories
    for subdir in src_dir.iterdir():
        if subdir.is_dir() and subdir.name not in {"__pycache__"}:
            for skip_dir in SKIP_DIRS:
                if skip_dir == "__pycache__":
                    continue
                nested = subdir / skip_dir
                if nested.exists():
                    rel = nested.relative_to(src_dir)
                    dst = build_output / rel
                    shutil.copytree(nested, dst, dirs_exist_ok=True)


def compile_sources(clean: bool = True) -> Path:
    """Compile all Python sources to native extensions.

    Returns the path to the compiled output directory.
    """
    modules = _find_compilable_modules(SRC_DIR)
    if not modules:
        print("ERROR: No compilable modules found")
        sys.exit(1)

    print(f"Found {len(modules)} modules to compile")

    # Clean previous build
    if clean and BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    # Create staging directory with source copy
    with tempfile.TemporaryDirectory() as tmpdir:
        staging = Path(tmpdir)
        staging_src = staging / "src"
        shutil.copytree(SRC_DIR, staging_src)

        # Generate Cython setup.py
        setup_path = _generate_setup_py(staging, modules)

        print(f"Compiling with Cython ({EXTENSION_SUFFIX} target)...")
        result = subprocess.run(
            [
                sys.executable, str(setup_path),
                "build_ext", "--inplace",
            ],
            cwd=staging,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print("Cython compilation FAILED:")
            print(result.stderr)
            sys.exit(1)

        print("Compilation successful")

        # Collect compiled files
        compiled_count = 0
        for so_file in staging_src.rglob(f"*{EXTENSION_SUFFIX}"):
            relative = so_file.relative_to(staging_src)
            target = BUILD_DIR / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(so_file, target)
            compiled_count += 1

    # Create __init__.py stubs
    _create_init_stubs(BUILD_DIR, SRC_DIR)

    # Copy non-code files (templates, etc.)
    _copy_non_code_files(BUILD_DIR, SRC_DIR)

    print(f"Compiled {compiled_count} modules → {BUILD_DIR}")
    return BUILD_DIR


def build_compiled_wheel() -> Path:
    """Build a wheel from compiled sources.

    Temporarily replaces src/ with compiled output, builds the wheel,
    then restores the original source.
    """
    compiled_dir = compile_sources()

    # Backup original src/
    backup_dir = PROJECT_ROOT / "build" / "_src_backup"
    if backup_dir.exists():
        shutil.rmtree(backup_dir)

    print("Building compiled wheel...")
    shutil.move(str(SRC_DIR), str(backup_dir))

    try:
        shutil.copytree(str(compiled_dir), str(SRC_DIR))

        # Build wheel
        result = subprocess.run(
            [sys.executable, "-m", "build", "--wheel"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print("Wheel build FAILED:")
            print(result.stderr)
            sys.exit(1)

    finally:
        # Restore original src/ in all cases
        shutil.rmtree(SRC_DIR, ignore_errors=True)
        shutil.move(str(backup_dir), str(SRC_DIR))

    # Find the built wheel
    wheels = sorted(DIST_DIR.glob("codetrust-*.whl"), key=os.path.getmtime)
    if not wheels:
        print("ERROR: No wheel found after build")
        sys.exit(1)

    wheel_path = wheels[-1]
    print(f"Compiled wheel: {wheel_path}")
    print(f"  Size: {wheel_path.stat().st_size:,} bytes")

    # Verify no .py files in wheel (except __init__.py)
    import zipfile
    with zipfile.ZipFile(wheel_path) as zf:
        py_files = [
            n for n in zf.namelist()
            if n.endswith(".py") and not n.endswith("__init__.py")
        ]
        if py_files:
            print(f"  WARNING: {len(py_files)} .py files still in wheel:")
            for pf in py_files[:5]:
                print(f"    - {pf}")
        else:
            print("  VERIFIED: No readable .py source in wheel (only __init__.py stubs)")

    return wheel_path


def main() -> None:
    """Entry point for the build script."""
    parser = argparse.ArgumentParser(
        description="Compile CodeTrust Python source with Cython",
    )
    parser.add_argument(
        "--wheel",
        action="store_true",
        help="Build a compiled wheel (default: compile only)",
    )
    parser.add_argument(
        "--no-clean",
        action="store_true",
        help="Do not clean previous build output",
    )
    args = parser.parse_args()

    # Check dependencies
    try:
        import Cython  # noqa: F401
    except ImportError:
        print("ERROR: Cython not installed. Run: pip install cython")
        sys.exit(1)

    if args.wheel:
        build_compiled_wheel()
    else:
        compile_sources(clean=not args.no_clean)


if __name__ == "__main__":
    main()
