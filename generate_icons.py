#!/usr/bin/env python3
"""Generate all CodeTrust logo assets from a single source image.

Usage:
    1. Save your logo (shield + text) as: icon.png (project root)
    2. Run: python generate_icons.py

Generates:
    - extension/images/icon.png  (256x256, shield cropped)
    - docs/logo.png              (840 wide, full banner)
    - docs/favicon.png           (64x64, shield cropped)
    - docs/favicon-32.png        (32x32)
    - docs/favicon-16.png        (16x16)
    - docs/apple-touch-icon.png  (180x180)
"""

from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("Install Pillow first: pip install Pillow")
    raise SystemExit(1)

ROOT = Path(__file__).parent
SOURCE = ROOT / "icon.png"


def extract_shield(img):
    """Crop the left portion (shield icon) and make it square."""
    w, h = img.size
    shield_w = int(w * 0.40)
    cropped = img.crop((0, 0, shield_w, h))
    size = max(cropped.size)
    square = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    offset_x = (size - cropped.width) // 2
    offset_y = (size - cropped.height) // 2
    square.paste(cropped, (offset_x, offset_y))
    return square


def save_resized(img, output, size):
    """Resize to square and save."""
    resized = img.resize((size, size), Image.LANCZOS)
    resized.save(output, "PNG")
    print(f"  OK  {output.relative_to(ROOT)}  ({size}x{size})")


def save_banner(img, output, width):
    """Resize keeping aspect ratio."""
    ratio = width / img.width
    height = int(img.height * ratio)
    resized = img.resize((width, height), Image.LANCZOS)
    resized.save(output, "PNG")
    print(f"  OK  {output.relative_to(ROOT)}  ({width}x{height})")


def main():
    if not SOURCE.exists():
        print(f"Missing: {SOURCE}")
        print("Save logo (shield + CodeTrust text) as icon.png in project root")
        return

    full = Image.open(SOURCE).convert("RGBA")
    print(f"Source: {full.width}x{full.height}")

    shield = extract_shield(full)
    print(f"Shield extracted: {shield.width}x{shield.height}")
    print()

    print("Generating icon assets...")
    save_resized(shield, ROOT / "extension" / "images" / "icon.png", 256)
    save_resized(shield, ROOT / "docs" / "favicon.png", 64)
    save_resized(shield, ROOT / "docs" / "favicon-32.png", 32)
    save_resized(shield, ROOT / "docs" / "favicon-16.png", 16)
    save_resized(shield, ROOT / "docs" / "apple-touch-icon.png", 180)

    print()
    print("Generating banner...")
    save_banner(full, ROOT / "docs" / "logo.png", 840)

    print()
    print("Done. All assets generated.")


if __name__ == "__main__":
    main()
