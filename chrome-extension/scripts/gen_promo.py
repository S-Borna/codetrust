# Copyright (c) Said Borna. All rights reserved.
"""Generates promo-440x280.png matching real CodeTrust website hero."""

from PIL import Image, ImageDraw, ImageFont

W, H = 440, 280

img = Image.new('RGB', (W, H), color=(8, 8, 16))
draw = ImageDraw.Draw(img)

# Subtle blue glow behind icon
glow = Image.new('RGBA', (W, H), (0, 0, 0, 0))
gd = ImageDraw.Draw(glow)
for r in range(160, 0, -1):
    alpha = int(22 * (1 - r / 160))
    gd.ellipse([64 - r, 64 - r, 64 + r, 64 + r], fill=(30, 80, 200, alpha))
img = Image.alpha_composite(img.convert('RGBA'), glow).convert('RGB')
draw = ImageDraw.Draw(img)

try:
    font_brand  = ImageFont.truetype('/System/Library/Fonts/Supplemental/Arial Bold.ttf', 42)
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
draw.text((112, 24), 'Code', fill=(255, 255, 255), font=font_brand)
code_w = int(draw.textlength('Code', font=font_brand))
draw.text((112 + code_w, 24), 'Trust', fill=(59, 130, 246), font=font_brand)

# Subtitle
draw.text((113, 74), 'AI-GOVERNANCE ENFORCEMENT PLATFORM', fill=(100, 116, 139), font=font_gov)

# Stats bar
bar_y = 114
draw.rounded_rectangle([28, bar_y, W - 28, bar_y + 26], radius=5,
                        fill=(10, 30, 10), outline=(34, 197, 94, 80))
draw.text((W // 2, bar_y + 13),
          'v2.7.0 — 1,898 tests — 10 layers — 280 rules — 46 endpoints',
          fill=(34, 197, 94), font=font_stats, anchor='mm')

# Headline
draw.text((28, 156), 'Prevent unsafe AI code', fill=(255, 255, 255), font=font_h1)
draw.text((28, 192), 'Before it executes', fill=(59, 130, 246), font=font_h1)

# Footer
draw.text((28, 256), 'codetrust.ai', fill=(51, 65, 85), font=font_gov)

for out in [
    '/Users/mrebadi/Desktop/DevOps/Codetrust/chrome-extension/store-assets/promo-440x280.png',
    '/Users/mrebadi/Desktop/codetrust-store-assets/promo-440x280.png',
]:
    img.save(out)
print('promo-440x280.png klar')
