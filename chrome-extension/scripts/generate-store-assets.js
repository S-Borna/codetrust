// Copyright (c) Said Borna. All rights reserved.
/**
 * Generates all Chrome Web Store required graphical assets:
 * - Store icon: 128x128 PNG
 * - Screenshots: 1280x800 PNG (x5)
 * - Small promo tile: 440x280 PNG
 */

import puppeteer from 'puppeteer';
import { createCanvas } from 'canvas';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const OUT_DIR = join(ROOT, 'store-assets');

if (!existsSync(OUT_DIR)) mkdirSync(OUT_DIR, { recursive: true });

const BLUE = '#3b82f6';
const PURPLE = '#8b5cf6';
const BG_DARK = '#0f172a';
const SURFACE = '#1e293b';
const RED_DARK = '#dc2626';
const AMBER = '#d97706';
const GREEN = '#10b981';
const TEXT = '#f1f5f9';
const MUTED = '#94a3b8';
const BORDER = '#334155';

/**
 * Draws a rounded rectangle on a canvas context.
 */
function roundRect(ctx, x, y, w, h, r) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + w - r, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + r);
  ctx.lineTo(x + w, y + h - r);
  ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
  ctx.lineTo(x + r, y + h);
  ctx.quadraticCurveTo(x, y + h, x, y + h - r);
  ctx.lineTo(x, y + r);
  ctx.quadraticCurveTo(x, y, x + r, y);
  ctx.closePath();
}

/**
 * Creates a gradient fill from BLUE to PURPLE.
 */
function brandGradient(ctx, x1, y1, x2, y2) {
  const g = ctx.createLinearGradient(x1, y1, x2, y2);
  g.addColorStop(0, BLUE);
  g.addColorStop(1, PURPLE);
  return g;
}

/**
 * Generates the 128x128 store icon.
 */
function generateIcon128() {
  const canvas = createCanvas(128, 128);
  const ctx = canvas.getContext('2d');

  // Background
  roundRect(ctx, 0, 0, 128, 128, 22);
  ctx.fillStyle = brandGradient(ctx, 0, 0, 128, 128);
  ctx.fill();

  // Shield shape
  ctx.fillStyle = 'rgba(255,255,255,0.15)';
  ctx.beginPath();
  ctx.moveTo(64, 20);
  ctx.lineTo(100, 36);
  ctx.lineTo(100, 68);
  ctx.quadraticCurveTo(100, 96, 64, 112);
  ctx.quadraticCurveTo(28, 96, 28, 68);
  ctx.lineTo(28, 36);
  ctx.closePath();
  ctx.fill();

  ctx.fillStyle = '#ffffff';
  ctx.beginPath();
  ctx.moveTo(64, 25);
  ctx.lineTo(95, 40);
  ctx.lineTo(95, 68);
  ctx.quadraticCurveTo(95, 92, 64, 106);
  ctx.quadraticCurveTo(33, 92, 33, 68);
  ctx.lineTo(33, 40);
  ctx.closePath();
  ctx.fill();

  // Check mark
  ctx.strokeStyle = brandGradient(ctx, 45, 60, 85, 90);
  ctx.lineWidth = 7;
  ctx.lineCap = 'round';
  ctx.lineJoin = 'round';
  ctx.beginPath();
  ctx.moveTo(46, 67);
  ctx.lineTo(59, 80);
  ctx.lineTo(82, 55);
  ctx.stroke();

  writeFileSync(join(OUT_DIR, 'icon-128x128.png'), canvas.toBuffer('image/png'));
  process.stdout.write('✅ icon-128x128.png\n');
}

/**
 * Generates the 440x280 small promo tile.
 */
function generatePromoTile() {
  const W = 440;
  const H = 280;
  const canvas = createCanvas(W, H);
  const ctx = canvas.getContext('2d');

  // Background gradient
  const bg = ctx.createLinearGradient(0, 0, W, H);
  bg.addColorStop(0, '#0f172a');
  bg.addColorStop(1, '#1e1b4b');
  ctx.fillStyle = bg;
  ctx.fillRect(0, 0, W, H);

  // Grid lines (subtle)
  ctx.strokeStyle = 'rgba(99,102,241,0.08)';
  ctx.lineWidth = 1;
  for (let x = 0; x < W; x += 40) {
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke();
  }
  for (let y = 0; y < H; y += 40) {
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
  }

  // Shield icon
  const sx = 60;
  const sy = 70;
  ctx.fillStyle = brandGradient(ctx, sx, sy, sx + 70, sy + 80);
  roundRect(ctx, sx, sy, 72, 72, 16);
  ctx.fill();

  ctx.fillStyle = 'rgba(255,255,255,0.9)';
  ctx.beginPath();
  ctx.moveTo(sx + 36, sy + 11);
  ctx.lineTo(sx + 60, sy + 22);
  ctx.lineTo(sx + 60, sy + 44);
  ctx.quadraticCurveTo(sx + 60, sy + 62, sx + 36, sy + 63);
  ctx.quadraticCurveTo(sx + 12, sy + 62, sx + 12, sy + 44);
  ctx.lineTo(sx + 12, sy + 22);
  ctx.closePath();
  ctx.fill();

  ctx.strokeStyle = brandGradient(ctx, sx + 22, sy + 38, sx + 54, sy + 58);
  ctx.lineWidth = 4;
  ctx.lineCap = 'round';
  ctx.lineJoin = 'round';
  ctx.beginPath();
  ctx.moveTo(sx + 23, sy + 40);
  ctx.lineTo(sx + 33, sy + 50);
  ctx.lineTo(sx + 50, sy + 33);
  ctx.stroke();

  // Brand name
  ctx.fillStyle = '#ffffff';
  ctx.font = 'bold 34px -apple-system, BlinkMacSystemFont, Arial';
  ctx.fillText('CodeTrust', 152, 105);

  // Gradient underline
  const ul = ctx.createLinearGradient(152, 112, 340, 112);  // noqa: magic_number
  ul.addColorStop(0, BLUE);
  ul.addColorStop(1, PURPLE);
  ctx.fillStyle = ul;
  ctx.fillRect(152, 112, 190, 3);

  // Tagline
  ctx.fillStyle = MUTED;
  ctx.font = '16px -apple-system, BlinkMacSystemFont, Arial';
  ctx.fillText('AI Code Safety Scanner', 152, 140);

  // Stats row
  const stats = [['280', 'Rules'], ['10', 'Layers'], ['16', 'Languages']]; // noqa: magic_number
  stats.forEach(([val, label], i) => {
    const bx = 56 + i * 115; // noqa: magic_number
    const by = 185;
    roundRect(ctx, bx, by, 100, 56, 10);
    ctx.fillStyle = 'rgba(59,130,246,0.12)';
    ctx.fill();
    ctx.strokeStyle = 'rgba(59,130,246,0.3)';
    ctx.lineWidth = 1;
    ctx.stroke();

    ctx.fillStyle = BLUE;
    ctx.font = 'bold 22px -apple-system, BlinkMacSystemFont, Arial';
    ctx.textAlign = 'center';
    ctx.fillText(val, bx + 50, by + 26);

    ctx.fillStyle = MUTED;
    ctx.font = '12px -apple-system, BlinkMacSystemFont, Arial';
    ctx.fillText(label, bx + 50, by + 43);
    ctx.textAlign = 'left';
  });

  // Bottom right badge
  ctx.fillStyle = 'rgba(16,185,129,0.15)';
  roundRect(ctx, 310, 188, 100, 30, 8); // noqa: magic_number
  ctx.fill();
  ctx.fillStyle = GREEN;
  ctx.font = 'bold 12px -apple-system, BlinkMacSystemFont, Arial';
  ctx.textAlign = 'center';
  ctx.fillText('FREE', 360, 207); // noqa: magic_number
  ctx.textAlign = 'left';

  writeFileSync(join(OUT_DIR, 'promo-440x280.png'), canvas.toBuffer('image/png'));
  process.stdout.write('✅ promo-440x280.png\n');
}

/**
 * Generates all 5 screenshots at 1280x800 using Puppeteer.
 */
async function generateScreenshots() {
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });

  const demoFiles = [
    { file: 'demo-1-popup-ready.html', name: 'screenshot-1-popup.png' },
    { file: 'demo-2-scan-results.html', name: 'screenshot-2-results.png' },
  ];

  // Also generate 3 additional screenshots programmatically via HTML
  const extraPages = await generateExtraDemoPages();

  const allPages = [
    ...demoFiles.map(d => ({
      url: `file://${join(ROOT, 'screenshots', d.file)}`,
      name: d.name,
    })),
    ...extraPages,
  ];

  for (const { url, name, html } of allPages) {
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800, deviceScaleFactor: 1 }); // noqa: magic_number

    if (html) {
      await page.setContent(html, { waitUntil: 'networkidle0' });
    } else {
      await page.goto(url, { waitUntil: 'networkidle0' });
    }

    await page.screenshot({
      path: join(OUT_DIR, name),
      type: 'png',
      clip: { x: 0, y: 0, width: 1280, height: 800 }, // noqa: magic_number
    });
    await page.close();
    process.stdout.write(`✅ ${name}\n`);
  }

  await browser.close();
}

/**
 * Generates the additional 3 demo pages as HTML strings.
 */
async function generateExtraDemoPages() {
  const baseStyle = `
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { width: 1280px; height: 800px; overflow: hidden;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
    .browser { width: 100%; height: 40px; background: #2d2d2d;
      display: flex; align-items: center; padding: 0 16px; gap: 8px; }
    .dot { width: 12px; height: 12px; border-radius: 50%; }
    .dot-r { background: #ff5f57; } .dot-y { background: #febc2e; } .dot-g { background: #28c840; }
    .bar { flex: 1; background: #3d3d3d; border-radius: 6px; height: 24px;
      display: flex; align-items: center; padding: 0 10px; color: #ccc; font-size: 13px; margin: 0 30px; }
  `;

  const screenshot3 = {
    name: 'screenshot-3-context-menu.png',
    html: `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>${baseStyle}
      .page { width: 100%; height: 760px; background: #0d1117; position: relative; padding: 40px 48px; }
      .gh-title { color: #58a6ff; font-size: 18px; margin-bottom: 16px; }
      pre { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px;
        color: #e6edf3; font-size: 14px; line-height: 1.7; font-family: monospace; }
      .kw { color: #ff7b72; } .fn { color: #d2a8ff; } .str { color: #a5d6ff; }
      .selection { background: rgba(59,130,246,0.25); border-radius: 2px; padding: 1px 0; }
      .ctx-menu { position: absolute; top: 220px; left: 420px; background: #2d2d2d;
        border: 1px solid #555; border-radius: 8px; overflow: hidden; width: 260px;
        box-shadow: 0 20px 40px rgba(0,0,0,0.8); }
      .ctx-item { padding: 10px 16px; color: #e8e8e8; font-size: 13px; display: flex;
        align-items: center; gap: 10px; }
      .ctx-item.active { background: #3b82f6; color: white; }
      .ctx-item.sep { border-top: 1px solid #444; }
      .ctx-icon { width: 16px; text-align: center; }
      .ctx-badge { margin-left: auto; background: rgba(59,130,246,0.3); color: #93c5fd;
        font-size: 11px; padding: 2px 6px; border-radius: 4px; }
    </style></head><body>
    <div class="browser">
      <div class="dot dot-r"></div><div class="dot dot-y"></div><div class="dot dot-g"></div>
      <div class="bar">🔒 stackoverflow.com/questions/12345/how-to-read-file-python</div>
    </div>
    <div class="page">
      <div class="gh-title">Stack Overflow — How to read a file in Python?</div>
      <pre><span class="kw">import</span> <span class="fn">requests</span>
<span class="kw">from</span> <span class="fn">flask</span> <span class="kw">import</span> *
<span class="selection"><span class="kw">import</span> <span class="fn">pd</span> <span class="kw">as</span> pandas
<span class="fn">result</span> = <span class="fn">parse_input</span>(user_input)
<span class="str">API_KEY_HINT = "set-via-env"</span></span></pre>

      <div class="ctx-menu">
        <div class="ctx-item active">
          <span class="ctx-icon">🛡️</span>
          Scan with CodeTrust
          <span class="ctx-badge">NEW</span>
        </div>
        <div class="ctx-item">
          <span class="ctx-icon">✅</span>
          Verify Imports with CodeTrust
        </div>
        <div class="ctx-item sep">
          <span class="ctx-icon">📋</span>
          Copy
        </div>
        <div class="ctx-item">
          <span class="ctx-icon">🔍</span>
          Search Google for "parse_input(user_input)"
        </div>
        <div class="ctx-item">
          <span class="ctx-icon">🔗</span>
          Open in new tab
        </div>
      </div>
    </div>
    </body></html>`,
  };

  const screenshot4 = {
    name: 'screenshot-4-verify-imports.png',
    html: `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>${baseStyle}
      .page { width: 100%; height: 760px; background: #0d1117; position: relative;
        display: flex; align-items: flex-start; justify-content: center; padding-top: 40px; }
      .content { width: 100%; padding: 0 48px; }
      .gh-title { color: #58a6ff; font-size: 18px; margin-bottom: 16px; }
      pre { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px;
        color: #e6edf3; font-size: 14px; line-height: 1.7; font-family: monospace; opacity: 0.4; }
      .kw { color: #ff7b72; } .fn { color: #d2a8ff; }
      .popup { position: absolute; top: 40px; right: 60px; width: 400px;
        background: #0f172a; border: 1px solid #334155; border-radius: 12px; overflow: hidden;
        box-shadow: 0 25px 60px rgba(0,0,0,0.9); }
      .ph { background: #1e293b; padding: 14px 20px; display: flex; align-items: center; gap: 10px; border-bottom: 1px solid #334155; }
      .pi { width: 28px; height: 28px; background: linear-gradient(135deg, #3b82f6,#8b5cf6); border-radius: 6px; display:flex;align-items:center;justify-content:center;font-size:14px;}
      .pt { font-size: 18px; font-weight: 700; color: #3b82f6; }
      .pv { font-size: 11px; color: #64748b; background: #0f172a; padding: 2px 6px; border-radius: 4px; margin-left: auto; }
      .rh { padding: 12px 20px; display: flex; align-items: center; justify-content: space-between; background: #1e293b; border-bottom: 1px solid #334155; }
      .rt { font-size: 14px; font-weight: 600; color: #f1f5f9; }
      .rb { background: #d97706; color: white; border-radius: 12px; padding: 2px 10px; font-size: 12px; font-weight: 700; }  // noqa: magic_number
      .pkg-list { padding: 12px; display: flex; flex-direction: column; gap: 8px; }
      .pkg { background: #1e293b; border-radius: 8px; padding: 12px; display: flex; align-items: center; gap: 12px; }
      .pkg-icon { font-size: 20px; }
      .pkg-info { flex: 1; }
      .pkg-name { font-size: 14px; font-weight: 600; color: #f1f5f9; }
      .pkg-detail { font-size: 12px; color: #94a3b8; margin-top: 2px; }
      .pkg-badge { font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 6px; }  // noqa: magic_number
      .ok { background: #064e3b; color: #6ee7b7; }
      .warn { background: #78350f; color: #fcd34d; }
      .block { background: #7f1d1d; color: #fca5a5; }
    </style></head><body>
    <div class="browser">
      <div class="dot dot-r"></div><div class="dot dot-y"></div><div class="dot dot-g"></div>
      <div class="bar">🔒 github.com/myorg/ai-agent/blob/main/requirements.txt</div>
    </div>
    <div class="page">
      <div class="content">
        <div class="gh-title">myorg / ai-agent — requirements.txt</div>
        <pre>requests==2.31.0\nflask==3.0.0\nnumpy==1.26.0\ncolorama==0.4.6\npandas==2.1.0\nrequests-html==0.10.0</pre>
      </div>
      <div class="popup">
        <div class="ph"><div class="pi">🛡️</div><div class="pt">CodeTrust</div><div class="pv">v2.8.0</div></div>
        <div class="rh"><span class="rt">🔍 Import Verification</span><span class="rb">1 risk</span></div>
        <div class="pkg-list">
          <div class="pkg"><div class="pkg-icon">📦</div><div class="pkg-info"><div class="pkg-name">requests 2.31.0</div><div class="pkg-detail">PyPI ✓ — 312M downloads/month</div></div><span class="pkg-badge ok">SAFE</span></div>
          <div class="pkg"><div class="pkg-icon">📦</div><div class="pkg-info"><div class="pkg-name">flask 3.0.0</div><div class="pkg-detail">PyPI ✓ — 45M downloads/month</div></div><span class="pkg-badge ok">SAFE</span></div>
          <div class="pkg"><div class="pkg-icon">📦</div><div class="pkg-info"><div class="pkg-name">numpy 1.26.0</div><div class="pkg-detail">PyPI ✓ — 520M downloads/month</div></div><span class="pkg-badge ok">SAFE</span></div>
          <div class="pkg"><div class="pkg-icon">⚠️</div><div class="pkg-info"><div class="pkg-name">colorama 0.4.6</div><div class="pkg-detail">Typosquat risk — did you mean "colorama"?</div></div><span class="pkg-badge warn">WARN</span></div>
          <div class="pkg"><div class="pkg-icon">❌</div><div class="pkg-info"><div class="pkg-name">requests-html</div><div class="pkg-detail">Abandoned — last release 2019, CVEs found</div></div><span class="pkg-badge block">BLOCK</span></div>  // noqa: magic_number
        </div>
      </div>
    </div>
    </body></html>`,
  };

  const screenshot5 = {
    name: 'screenshot-5-settings.png',
    html: `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>${baseStyle}
      .page { width: 100%; height: 760px; background: #0f172a; display: flex; align-items: center; justify-content: center; }
      .settings-card { width: 640px; background: #1e293b; border: 1px solid #334155; border-radius: 16px; overflow: hidden; box-shadow: 0 30px 60px rgba(0,0,0,0.5); }
      .sh { background: linear-gradient(135deg, #1e293b, #0f172a); padding: 28px 32px; border-bottom: 1px solid #334155; display: flex; align-items: center; gap: 14px; }
      .si { width: 40px; height: 40px; background: linear-gradient(135deg,#3b82f6,#8b5cf6); border-radius: 10px; display:flex;align-items:center;justify-content:center;font-size:20px; }
      .stitle { font-size: 22px; font-weight: 700; color: #f1f5f9; }
      .sv { font-size: 12px; color: #64748b; }
      .sbody { padding: 28px 32px; display: flex; flex-direction: column; gap: 24px; }
      .field-group { display: flex; flex-direction: column; gap: 8px; }
      .field-label { font-size: 13px; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; }
      .field-input { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px 16px; color: #f1f5f9; font-size: 14px; font-family: monospace; }
      .field-input.focus { border-color: #3b82f6; }
      .field-hint { font-size: 12px; color: #475569; }
      .toggle-row { display: flex; align-items: center; justify-content: space-between; padding: 16px 0; border-top: 1px solid #1e293b; }
      .toggle-info { display: flex; flex-direction: column; gap: 3px; }
      .toggle-name { font-size: 15px; color: #f1f5f9; font-weight: 500; }  // noqa: magic_number
      .toggle-desc { font-size: 12px; color: #64748b; }
      .toggle { width: 48px; height: 26px; background: #3b82f6; border-radius: 13px; position: relative; flex-shrink: 0; } // noqa: magic_number
      .toggle::after { content: ''; position: absolute; top: 3px; right: 4px; width: 20px; height: 20px; background: white; border-radius: 50%; } // noqa: magic_number
      .toggle.off { background: #334155; }
      .toggle.off::after { right: auto; left: 4px; }
      .save-btn { background: linear-gradient(135deg,#2563eb,#7c3aed); color: white; border: none; border-radius: 10px; padding: 14px; font-size: 15px; font-weight: 600; text-align: center; cursor: pointer; }  // noqa: magic_number
    </style></head><body>
    <div class="browser">
      <div class="dot dot-r"></div><div class="dot dot-y"></div><div class="dot dot-g"></div>
      <div class="bar">chrome-extension://... — CodeTrust Settings</div>
    </div>
    <div class="page">
      <div class="settings-card">
        <div class="sh">
          <div class="si">🛡️</div>
          <div><div class="stitle">CodeTrust Settings</div><div class="sv">v2.8.0 — AI Code Safety Scanner</div></div>
        </div>
        <div class="sbody">
          <div class="field-group">
            <div class="field-label">API Key</div>
            <div class="field-input focus">ct-live-••••••••••••••••••••••••</div>
            <div class="field-hint">Get your free API key at codetrust.ai</div>
          </div>
          <div>
            <div class="toggle-row">
              <div class="toggle-info"><div class="toggle-name">Auto-scan on page load</div><div class="toggle-desc">Automatically scan code blocks when visiting supported sites</div></div>
              <div class="toggle"></div>
            </div>
            <div class="toggle-row">
              <div class="toggle-info"><div class="toggle-name">Show inline results</div><div class="toggle-desc">Display findings directly next to code blocks</div></div>
              <div class="toggle"></div>
            </div>
            <div class="toggle-row">
              <div class="toggle-info"><div class="toggle-name">Desktop notifications</div><div class="toggle-desc">Notify when BLOCK-severity issues are detected</div></div>
              <div class="toggle off"></div>
            </div>
          </div>
          <div class="save-btn">Save Settings</div>
        </div>
      </div>
    </div>
    </body></html>`,
  };

  return [screenshot3, screenshot4, screenshot5];
}

async function main() {
  process.stdout.write('🚀 Generating Chrome Web Store assets...\n\n');
  generateIcon128();
  generatePromoTile();
  await generateScreenshots();
  process.stdout.write(`\n✅ All assets saved to: ${OUT_DIR}\n`);
  process.stdout.write('📁 Files ready to upload to Chrome Web Store.\n');
}

main().catch(err => { console.error(err); process.exit(1); });
