"""Generate PNG icons from the shield SVG for extension, docs, and PyPI."""

import cairosvg

SHIELD_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 140">
  <defs>
    <linearGradient id="g" x1="60" y1="8" x2="60" y2="132" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="#3b82f6" stop-opacity="0.25"/>
      <stop offset="100%" stop-color="#1d4ed8" stop-opacity="0.03"/>
    </linearGradient>
    <linearGradient id="s" x1="60" y1="8" x2="60" y2="132" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="#60a5fa"/>
      <stop offset="100%" stop-color="#1d4ed8"/>
    </linearGradient>
    <radialGradient id="glow" cx="0.5" cy="0.45" r="0.5">
      <stop offset="0%" stop-color="#22c55e" stop-opacity="0.12"/>
      <stop offset="60%" stop-color="#3b82f6" stop-opacity="0.06"/>
      <stop offset="100%" stop-color="#3b82f6" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="120" height="140" fill="#050507" rx="8"/>
  <path d="M60 8L12 30v40c0 32 20 52 48 62 28-10 48-30 48-62V30L60 8z" fill="url(#g)" stroke="url(#s)" stroke-width="4"/>
  <path d="M60 18L22 36v32c0 26 16 44 38 52 22-8 38-26 38-52V36L60 18z" fill="none" stroke="rgba(96,165,250,0.1)" stroke-width="1"/>
  <text x="60" y="76" text-anchor="middle" font-family="monospace" font-size="40" font-weight="700" fill="#22c55e">&#60;/&#62;</text>
  <path d="M44 94l12 12 20-24" stroke="#3b82f6" stroke-width="5" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
  <circle cx="60" cy="70" r="35" fill="url(#glow)" opacity="0.6"/>
</svg>"""

LOGO_SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="420" height="120" viewBox="0 0 420 120">
  <rect width="420" height="120" fill="#050507" rx="12"/>
  <g transform="translate(30, 5) scale(0.78)">
    <defs>
      <linearGradient id="g2" x1="60" y1="8" x2="60" y2="132" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stop-color="#3b82f6" stop-opacity="0.25"/>
        <stop offset="100%" stop-color="#1d4ed8" stop-opacity="0.03"/>
      </linearGradient>
      <linearGradient id="s2" x1="60" y1="8" x2="60" y2="132" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stop-color="#60a5fa"/>
        <stop offset="100%" stop-color="#1d4ed8"/>
      </linearGradient>
      <radialGradient id="glow2" cx="0.5" cy="0.45" r="0.5">
        <stop offset="0%" stop-color="#22c55e" stop-opacity="0.12"/>
        <stop offset="60%" stop-color="#3b82f6" stop-opacity="0.06"/>
        <stop offset="100%" stop-color="#3b82f6" stop-opacity="0"/>
      </radialGradient>
    </defs>
    <path d="M60 8L12 30v40c0 32 20 52 48 62 28-10 48-30 48-62V30L60 8z" fill="url(#g2)" stroke="url(#s2)" stroke-width="4"/>
    <path d="M60 18L22 36v32c0 26 16 44 38 52 22-8 38-26 38-52V36L60 18z" fill="none" stroke="rgba(96,165,250,0.1)" stroke-width="1"/>
    <text x="60" y="76" text-anchor="middle" font-family="monospace" font-size="40" font-weight="700" fill="#22c55e">&#60;/&#62;</text>
    <path d="M44 94l12 12 20-24" stroke="#3b82f6" stroke-width="5" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
    <circle cx="60" cy="70" r="35" fill="url(#glow2)" opacity="0.6"/>
  </g>
  <text x="260" y="73" text-anchor="middle" font-family="sans-serif" font-size="42" font-weight="700">
    <tspan fill="#e8e8ec">Code</tspan><tspan fill="#3b82f6">Trust</tspan>
  </text>
</svg>"""

if __name__ == "__main__":
    import os

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Extension icon (256x256 square with dark bg)
    ext_icon = os.path.join(root, "extension", "images", "icon.png")
    cairosvg.svg2png(bytestring=SHIELD_SVG.encode(), write_to=ext_icon, output_width=256, output_height=256)
    print(f"Extension icon: {ext_icon}")

    # Docs favicons
    for size, name in [(180, "apple-touch-icon.png"), (32, "favicon-32.png"), (16, "favicon-16.png")]:
        path = os.path.join(root, "docs", name)
        cairosvg.svg2png(bytestring=SHIELD_SVG.encode(), write_to=path, output_width=size, output_height=size)
        print(f"Docs icon ({size}px): {path}")

    # README/PyPI logo
    logo_path = os.path.join(root, "docs", "logo.png")
    cairosvg.svg2png(bytestring=LOGO_SVG.encode(), write_to=logo_path, output_width=840, output_height=240)
    print(f"Logo: {logo_path}")

    print("All icons generated!")
