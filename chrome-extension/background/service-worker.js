// Copyright (c) Said Borna. All rights reserved.

const API_BASE_URL = "https://api.codetrust.ai";
const CONTEXT_MENU_SCAN_ID = "codetrust-scan-selection";
const CONTEXT_MENU_VERIFY_ID = "codetrust-verify-imports";

/**
 * Create context menu items when extension is installed.
 */
chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: CONTEXT_MENU_SCAN_ID,
        title: "Scan with CodeTrust",
        contexts: ["selection"],
    });

    chrome.contextMenus.create({
        id: CONTEXT_MENU_VERIFY_ID,
        title: "Verify Imports with CodeTrust",
        contexts: ["selection"],
    });
});

/**
 * Handle context menu clicks.
 * @param {chrome.contextMenus.OnClickData} info
 * @param {chrome.tabs.Tab} tab
 */
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    if (!info.selectionText || !tab.id) {
        return;
    }

    const selectedCode = info.selectionText;

    if (info.menuItemId === CONTEXT_MENU_SCAN_ID) {
        await scanCode(selectedCode, tab.id);
    } else if (info.menuItemId === CONTEXT_MENU_VERIFY_ID) {
        await verifyCode(selectedCode, tab.id);
    }
});

/**
 * Scan selected code via the CodeTrust API.
 * @param {string} code - The code to scan.
 * @param {number} tabId - The tab ID to send results to.
 */
async function scanCode(code, tabId) {
    try {
        const apiKey = await getApiKey();
        const response = await fetch(API_BASE_URL + "/v1/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                ...(apiKey ? { "X-API-Key": apiKey } : {}),
            },
            body: JSON.stringify({
                code: code,
                language: "python",
                scan_type: "static",
            }),
        });

        if (!response.ok) {
            throw new Error("API error: " + response.status);
        }

        const result = await response.json();
        const findingsCount = result.findings ? result.findings.length : 0;

        chrome.notifications.create({
            type: "basic",
            iconUrl: "icons/icon-128.png",
            title: "CodeTrust Scan Complete",
            message: findingsCount + " issues found in selected code.",
        });

        chrome.tabs.sendMessage(tabId, {
            action: "showResults",
            findings: result.findings || [],
            trustScore: result.trust_score || null,
        });
    } catch (error) {
        chrome.notifications.create({
            type: "basic",
            iconUrl: "icons/icon-128.png",
            title: "CodeTrust Error",
            message: "Scan failed: " + error.message,
        });
    }
}

/**
 * Verify imports in selected code via the CodeTrust API.
 * @param {string} code - The code to verify.
 * @param {number} tabId - The tab ID to send results to.
 */
async function verifyCode(code, tabId) {
    try {
        const apiKey = await getApiKey();
        const response = await fetch(API_BASE_URL + "/v1/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                ...(apiKey ? { "X-API-Key": apiKey } : {}),
            },
            body: JSON.stringify({
                code: code,
                language: "python",
                scan_type: "deep",
            }),
        });

        if (!response.ok) {
            throw new Error("API error: " + response.status);
        }

        const result = await response.json();
        const importFindings = (result.findings || []).filter(
            (f) =>
                f.rule_id.includes("import") ||
                f.rule_id.includes("hallucin") ||
                f.rule_id.includes("registry")
        );

        chrome.notifications.create({
            type: "basic",
            iconUrl: "icons/icon-128.png",
            title: "CodeTrust Import Verification",
            message: importFindings.length + " import issues found.",
        });

        chrome.tabs.sendMessage(tabId, {
            action: "showResults",
            findings: importFindings,
            trustScore: result.trust_score || null,
        });
    } catch (error) {
        chrome.notifications.create({
            type: "basic",
            iconUrl: "icons/icon-128.png",
            title: "CodeTrust Error",
            message: "Verification failed: " + error.message,
        });
    }
}

/**
 * Get the stored API key from Chrome storage.
 * @returns {Promise<string>}
 */
async function getApiKey() {
    return new Promise((resolve) => {
        chrome.storage.sync.get(["codetrust_api_key"], (result) => {
            resolve(result.codetrust_api_key || "");
        });
    });
}
