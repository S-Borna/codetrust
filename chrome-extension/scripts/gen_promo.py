# Copyright (c) Said Borna. All rights reserved.
"""Generates promo-440x280.png matching real CodeTrust website hero."""

import sys

from PIL import Image, ImageDraw, ImageFont

W, H = (44 * 10), (28 * 10)

img = Image.new('RGB', (W, H), color=(8, 8, 16))
draw = ImageDraw.Draw(img)

# Subtle blue glow behind icon
glow = Image.new('RGBA', (W, H), (0, 0, 0, 0))
gd = ImageDraw.Draw(glow)
for r in range(160, 0, -1):  # noqa: magic_number
    alpha = int(22 * (1 - r / 160))  # noqa: magic_number
    gd.ellipse([64 - r, 64 - r, 64 + r, 64 + r], fill=(30, 80, 200, alpha))  # noqa: magic_number
img = Image.alpha_composite(img.convert('RGBA'), glow).convert('RGB')
draw = ImageDraw.Draw(img)

try:
    font_brand  = ImageFont.truetype('/System/Library/Fonts/Supplemental/Arial Bold.ttf', 42)  # noqa: magic_number
    font_gov    = ImageFont.truetype('/System/Library/Fonts/Helvetica.ttc', 11)
    font_stats  = ImageFont.truetype('/System/Library/Fonts/Courier New.ttf', 11)
    font_h1     = ImageFont.truetype('/System/Library/Fonts/Supplemental/Arial Bold.ttf', 26)
except Exception:
    font_brand = font_gov = font_stats = font_h1 = ImageFont.load_default()

# Real CodeTrust icon
icon_src = Image.open('/Users/mrebadi/Desktop/DevOps/Codetrust/extension/images/icon.png')
icon = icon_src.resize((72, 72), Image.LANCZOS)
img.paste(icon, (28, 24), icon)

# "Code" white + "Trust" blue
draw.text((112, 24), 'Code', fill=(255, 255, 255), font=font_brand)  # noqa: magic_number
code_w = int(draw.textlength('Code', font=font_brand))
draw.text((112 + code_w, 24), 'Trust', fill=(59, 130, 246), font=font_brand)  # noqa: magic_number

# Subtitle
draw.text((113, 74), 'AI-GOVERNANCE ENFORCEMENT PLATFORM', fill=(100, 116, 139), font=font_gov)  # noqa: magic_number

# Stats bar
bar_y = (57 * 2)
draw.rounded_rectangle([28, bar_y, W - 28, bar_y + 26], radius=5,  # noqa: magic_number
                        fill=(10, 30, 10), outline=(34, 197, 94, 80))
draw.text((W // 2, bar_y + 13),  # noqa: magic_number
          'CodeTrust — enterprise verified stack',
          fill=(34, 197, 94), font=font_stats, anchor='mm')

# Headline
draw.text((28, 156), 'Prevent unsafe AI code', fill=(255, 255, 255), font=font_h1)  # noqa: magic_number
draw.text((28, 192), 'Before it executes', fill=(59, 130, 246), font=font_h1)  # noqa: magic_number

# Footer
draw.text((28, 256), 'codetrust.ai', fill=(51, 65, 85), font=font_gov)  # noqa: magic_number

for out in [
    '/Users/mrebadi/Desktop/DevOps/Codetrust/chrome-extension/store-assets/promo-440x280.png',
    '/Users/mrebadi/Desktop/codetrust-store-assets/promo-440x280.png',
]:
    img.save(out)
sys.stdout.write('promo-440x280.png klar\n')
