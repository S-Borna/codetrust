// Copyright (c) Said Borna. All rights reserved.
// Generate Chrome extension icons from the VS Code extension icon.
// Usage: node scripts/generate-icons.js

const fs = require("fs");
const path = require("path");

const ICON_DIR = path.join(__dirname, "..", "icons");
const SOURCE_ICON = path.join(__dirname, "..", "..", "extension", "images", "icon.png");
const SIZES = [16, 32, 48, 128];

/**
 * Create icons directory and copy source icon.
 * For production, use a proper image resizer (sharp, jimp, etc.).
 * This script copies the source icon as a placeholder for all sizes.
 */
function generateIcons() {
    if (!fs.existsSync(ICON_DIR)) {
        fs.mkdirSync(ICON_DIR, { recursive: true });
    }

    if (!fs.existsSync(SOURCE_ICON)) {
        console.error("Source icon not found:", SOURCE_ICON);
        process.stdout.write("Please place icon.png in extension/images/\n");
        process.exit(1);
    }

    const iconBuffer = fs.readFileSync(SOURCE_ICON);

    for (const size of SIZES) {
        const targetPath = path.join(ICON_DIR, "icon-" + size + ".png");
        fs.writeFileSync(targetPath, iconBuffer);
        process.stdout.write("Created: " + targetPath + " (" + size + "x" + size + ")\n");
    }

    process.stdout.write("\nDone! For production, resize icons properly using:\n");
    process.stdout.write("  npx sharp-cli resize " + SIZES.join(" ") + " --input " + SOURCE_ICON + "\n");
}

generateIcons();
