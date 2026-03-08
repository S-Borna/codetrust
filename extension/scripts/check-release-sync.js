const fs = require("fs");
const path = require("path");

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const EXTENSION_PACKAGE_PATH = path.resolve(__dirname, "..", "package.json");
const PYPROJECT_PATH = path.resolve(REPO_ROOT, "pyproject.toml");
const WEBSITE_PATH = path.resolve(REPO_ROOT, "docs", "index.html");
const CHANGELOG_PATH = path.resolve(REPO_ROOT, "CHANGELOG.md");
const ROOT_README_PATH = path.resolve(REPO_ROOT, "README.md");
const EXTENSION_README_PATH = path.resolve(REPO_ROOT, "extension", "README.md");

const FORBIDDEN_PUBLIC_DOC_STRINGS = [
    "SESSION_LOG",
    "PLAN.md",
    "SPEC.md",
    "](CLAUDE.md)",   // internal markdown link to dev guidelines — NOT ~/.claude/CLAUDE.md
    "docs/backlog-status.md",
];

function readText(filePath) {
    return fs.readFileSync(filePath, "utf8");
}

function parsePythonVersion(pyprojectText) {
    const match = pyprojectText.match(/\nversion\s*=\s*"([^"]+)"/);
    if (!match) {
        throw new Error("Could not parse Python package version from pyproject.toml");
    }
    return match[1];
}

function ensureContains(content, needle, sourceName, failures) {
    if (!content.includes(needle)) {
        failures.push(`${sourceName} is missing: ${needle}`);
    }
}

function ensureNotContains(content, needles, sourceName, failures) {
    for (const needle of needles) {
        if (content.includes(needle)) {
            failures.push(`${sourceName} contains forbidden internal reference: ${needle}`);
        }
    }
}

function main() {
    const extensionPackage = JSON.parse(readText(EXTENSION_PACKAGE_PATH));
    const extensionVersion = extensionPackage.version;
    const pyprojectVersion = parsePythonVersion(readText(PYPROJECT_PATH));
    const website = readText(WEBSITE_PATH);
    const changelog = readText(CHANGELOG_PATH);
    const rootReadme = readText(ROOT_README_PATH);
    const extensionReadme = readText(EXTENSION_README_PATH);

    const failures = [];

    if (extensionVersion !== pyprojectVersion) {
        failures.push(
            `Version mismatch: extension/package.json=${extensionVersion}, pyproject.toml=${pyprojectVersion}`,
        );
    }
    ensureContains(website, `v${extensionVersion}`, "docs/index.html", failures);
    ensureContains(changelog, `## [${extensionVersion}]`, "CHANGELOG.md", failures);

    ensureNotContains(rootReadme, FORBIDDEN_PUBLIC_DOC_STRINGS, "README.md", failures);
    ensureNotContains(extensionReadme, FORBIDDEN_PUBLIC_DOC_STRINGS, "extension/README.md", failures);

    if (failures.length > 0) {
        console.error("\nRelease sync guard failed:\n");
        for (const failure of failures) {
            console.error(`- ${failure}`);
        }
        console.error("\nSync docs/version strings before running Marketplace package/publish.\n");
        process.exit(1);
    }

    process.stdout.write(
        `Release sync OK: v${extensionVersion} aligned across extension, pyproject, changelog, and website.\n`,
    );
}

main();