#!/usr/bin/env python3
"""Export the OpenAPI spec from the FastAPI app to a static JSON file.

Usage:
    python scripts/export_openapi.py
    # Outputs: docs/openapi.json
"""

import json
from pathlib import Path

from src.api import app


def main() -> None:
    spec = app.openapi()
    output = Path(__file__).resolve().parent.parent / "docs" / "openapi.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(spec, indent=2, ensure_ascii=False) + "\n")
    print(f"OpenAPI spec written to {output}  ({len(spec['paths'])} endpoints)")


if __name__ == "__main__":
    main()
