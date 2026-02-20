// Copyright (c) 2026 Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.

/**
 * Post-build obfuscation for CodeTrust VS Code extension.
 *
 * Runs AFTER esbuild minification. Applies javascript-obfuscator with:
 *   - Control flow flattening (makes code logic hard to follow)
 *   - String encryption (hides API URLs, command names, error messages)
 *   - Dead code injection (adds noise to deter analysis)
 *   - Identifier mangling (already done by esbuild, reinforced here)
 *
 * This transforms the minified bundle from "reformattable" to "genuinely hard
 * to reverse engineer." The combination of esbuild minification + obfuscation
 * is significantly harder to defeat than either alone.
 *
 * Usage:
 *   node scripts/obfuscate.js         (called automatically by `npm run bundle`)
 */

const JavaScriptObfuscator = require("javascript-obfuscator");
const fs = require("fs");
const path = require("path");

const BUNDLE_PATH = path.join(__dirname, "..", "out", "extension.js");
const COPYRIGHT_BANNER =
    "// Copyright (c) 2026 Said Borna. All rights reserved. Proprietary.\n";

/** @type {import('javascript-obfuscator').ObfuscatorOptions} */
const OBFUSCATION_OPTIONS = {
    // --- Control Flow ---
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: 0.5,
    deadCodeInjection: true,
    deadCodeInjectionThreshold: 0.2,

    // --- String Protection ---
    stringArray: true,
    stringArrayEncoding: ["base64"],
    stringArrayThreshold: 0.5,
    stringArrayRotate: true,
    stringArrayShuffle: true,
    stringArrayWrappersCount: 1,
    stringArrayWrappersType: "variable",

    // --- Identifier Protection ---
    identifierNamesGenerator: "hexadecimal",
    renameGlobals: false, // Don't rename `exports`, `require`, `module`

    // --- Misc ---
    compact: true,
    simplify: true,
    splitStrings: true,
    splitStringsChunkLength: 5,
    transformObjectKeys: true,

    // --- Performance-safe options ---
    // These are disabled to avoid breaking VS Code extension runtime:
    selfDefending: false, // Can break in strict Node.js
    disableConsoleOutput: false, // Extension needs console for activation logs
    debugProtection: false, // Not needed for production extension
    domainLock: [], // Not applicable to Node.js extensions
    target: "node",
    sourceMap: false,
};

function main() {
    if (!fs.existsSync(BUNDLE_PATH)) {
        console.error(
            `[obfuscate] ERROR: Bundle not found at ${BUNDLE_PATH}. Run esbuild first.`
        );
        process.exit(1);
    }

    const originalCode = fs.readFileSync(BUNDLE_PATH, "utf8");
    const originalSize = Buffer.byteLength(originalCode, "utf8");

    console.log(
        `[obfuscate] Processing ${BUNDLE_PATH} (${(originalSize / 1024).toFixed(1)} KB)...`
    );

    const result = JavaScriptObfuscator.obfuscate(originalCode, OBFUSCATION_OPTIONS);
    const obfuscatedCode = COPYRIGHT_BANNER + result.getObfuscatedCode();
    const obfuscatedSize = Buffer.byteLength(obfuscatedCode, "utf8");

    fs.writeFileSync(BUNDLE_PATH, obfuscatedCode, "utf8");

    const ratio = (obfuscatedSize / originalSize).toFixed(1);
    console.log(
        `[obfuscate] Done: ${(originalSize / 1024).toFixed(1)} KB → ${(obfuscatedSize / 1024).toFixed(1)} KB (${ratio}x)`
    );
    console.log("[obfuscate] Applied: control flow flattening, string encryption, dead code injection");
}

main();
