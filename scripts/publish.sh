#!/bin/bash
# CodeTrust publish script — reads tokens from .env, publishes everywhere.
# Usage: bash scripts/publish.sh
#
# Publishes to: PyPI, VS Code Marketplace, Open VSX
# Requires: twine, vsce, ovsx (all via npm/pip)

set -euo pipefail
cd "$(dirname "$0")/.."

# Load tokens from .env
if [ ! -f .env ]; then
    echo "ERROR: .env not found in repo root. Create it with VSCE_PAT and OVSX_PAT."
    exit 1
fi

set -a
source .env
set +a

VERSION=$(python -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")
echo "Publishing CodeTrust v${VERSION}"
echo "================================"

# 1. Build wheel
echo ""
echo "[1/4] Building wheel..."
python -m build --wheel
WHEEL="dist/codetrust-${VERSION}-py3-none-any.whl"
if [ ! -f "$WHEEL" ]; then
    echo "ERROR: Wheel not found: $WHEEL"
    exit 1
fi
echo "  OK: $WHEEL"

# 2. PyPI
echo ""
echo "[2/4] Publishing to PyPI..."
twine upload "$WHEEL"
echo "  OK: https://pypi.org/project/codetrust/${VERSION}/"

# 3. VS Code Marketplace
echo ""
echo "[3/4] Publishing to VS Code Marketplace..."
if [ -z "${VSCE_PAT:-}" ]; then
    echo "  SKIP: VSCE_PAT not set in .env"
else
    cd extension
    VSCE_PAT="$VSCE_PAT" npx vsce publish
    echo "  OK: https://marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust"
    cd ..
fi

# 4. Open VSX
echo ""
echo "[4/4] Publishing to Open VSX..."
VSIX="extension/codetrust-${VERSION}.vsix"
if [ ! -f "$VSIX" ]; then
    echo "  Packaging VSIX first..."
    cd extension && npx vsce package && cd ..
fi
if [ -z "${OVSX_PAT:-}" ]; then
    echo "  SKIP: OVSX_PAT not set in .env"
else
    npx ovsx publish "$VSIX" -p "$OVSX_PAT"
    echo "  OK: https://open-vsx.org/extension/SaidBorna/codetrust"
fi

echo ""
echo "================================"
echo "CodeTrust v${VERSION} published."
echo "  PyPI:        https://pypi.org/project/codetrust/${VERSION}/"
echo "  Marketplace: https://marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust"
echo "  Open VSX:    https://open-vsx.org/extension/SaidBorna/codetrust"
echo "  Railway:     auto-deploys from main"
