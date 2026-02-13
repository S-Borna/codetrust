const fs = require("fs");
const path = require("path");

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const EXTENSION_PACKAGE_PATH = path.resolve(__dirname, "..", "package.json");
const PYPROJECT_PATH = path.resolve(REPO_ROOT, "pyproject.toml");
const WEBSITE_PATH = path.resolve(REPO_ROOT, "docs", "index.html");
const CHANGELOG_PATH = path.resolve(REPO_ROOT, "CHANGELOG.md");

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

function main() {
    const extensionPackage = JSON.parse(readText(EXTENSION_PACKAGE_PATH));
    const extensionVersion = extensionPackage.version;
    const pyprojectVersion = parsePythonVersion(readText(PYPROJECT_PATH));
    const website = readText(WEBSITE_PATH);
    const changelog = readText(CHANGELOG_PATH);

    const failures = [];

    if (extensionVersion !== pyprojectVersion) {
        failures.push(
            `Version mismatch: extension/package.json=${extensionVersion}, pyproject.toml=${pyprojectVersion}`,
        );
    }
    ensureContains(website, `v${extensionVersion}`, "docs/index.html", failures);
    ensureContains(changelog, `## [${extensionVersion}]`, "CHANGELOG.md", failures);

    if (failures.length > 0) {
        console.error("\nRelease sync guard failed:\n");
        for (const failure of failures) {
            console.error(`- ${failure}`);
        }
        console.error("\nSync docs/version strings before running Marketplace package/publish.\n");
        process.exit(1);
    }

    console.log(
        `Release sync OK: v${extensionVersion} aligned across extension, pyproject, changelog, and website.`,
    );
}

main();