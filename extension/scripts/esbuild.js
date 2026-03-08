// Copyright (c) Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.

/**
 * esbuild configuration for CodeTrust VS Code extension.
 *
 * Bundles all TypeScript source into a single minified file.
 * Purpose: IP protection — prevents trivial source extraction from .vsix.
 *
 * Usage:
 *   npm run bundle       (production — minified, no source maps)
 *   npm run compile      (development — readable, with type checking)
 */

const esbuild = require("esbuild");
const path = require("path");

const isWatch = process.argv.includes("--watch");

/** @type {import('esbuild').BuildOptions} */
const buildOptions = {
    entryPoints: [path.join(__dirname, "..", "src", "extension.ts")],
    bundle: true,
    outfile: path.join(__dirname, "..", "out", "extension.js"),
    external: ["vscode"],
    format: "cjs",
    platform: "node",
    target: "node18",
    minify: true,
    minifyWhitespace: true,
    minifyIdentifiers: true,
    minifySyntax: true,
    treeShaking: true,
    sourcemap: false,
    legalComments: "none",
    banner: {
        js: "// Copyright (c) Said Borna. All rights reserved. Proprietary.",
    },
    define: {
        "process.env.NODE_ENV": '"production"',
    },
    logLevel: "info",
};

async function main() {
    if (isWatch) {
        const ctx = await esbuild.context(buildOptions);
        await ctx.watch();
        process.stdout.write("[esbuild] watching for changes...\n");
    } else {
        await esbuild.build(buildOptions);
        process.stdout.write("[esbuild] extension bundled and minified successfully\n");
    }
}

main().catch((err) => {
    console.error("[esbuild] build failed:", err);
    process.exit(1);
});
