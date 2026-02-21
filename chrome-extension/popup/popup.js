// Copyright (c) Said Borna. All rights reserved.

const API_BASE_URL = "https://api.codetrust.ai";
const API_VERSION = "v1";

document.addEventListener("DOMContentLoaded", () => {
    const btnScanPage = document.getElementById("btn-scan-page");
    const btnScanSelection = document.getElementById("btn-scan-selection");
    const btnVerifyImports = document.getElementById("btn-verify-imports");
    const btnOptions = document.getElementById("btn-options");
    const statusDot = document.querySelector(".ct-dot");
    const statusText = document.getElementById("status-text");
    const resultsSection = document.getElementById("results-section");
    const resultsBody = document.getElementById("results-body");
    const findingsCount = document.getElementById("findings-count");
    const trustScoreSection = document.getElementById("trust-score-section");
    const trustScoreValue = document.getElementById("trust-score-value");
    const trustScoreFill = document.getElementById("trust-score-fill");

    btnScanPage.addEventListener("click", () => scanPageCode());
    btnScanSelection.addEventListener("click", () => scanSelection());
    btnVerifyImports.addEventListener("click", () => verifyImports());
    btnOptions.addEventListener("click", (event) => {
        event.preventDefault();
        chrome.runtime.openOptionsPage();
    });

    /**
     * Set the status indicator state.
     * @param {"ready" | "scanning" | "error" | "done"} state
     * @param {string} text
     */
    function setStatus(state, text) {
        statusDot.className = "ct-dot";
        if (state === "ready" || state === "done") {
            statusDot.classList.add("ct-dot--active");
        } else if (state === "scanning") {
            statusDot.classList.add("ct-dot--scanning");
        } else if (state === "error") {
            statusDot.classList.add("ct-dot--error");
        }
        statusText.textContent = text;
    }

    /**
     * Render scan findings in the results panel.
     * @param {Array<{rule_id: string, severity: string, message: string, suggestion?: string}>} findings
     * @param {number | null} trustScore
     */
    function renderResults(findings, trustScore) {
        resultsSection.style.display = "block";
        resultsBody.innerHTML = "";

        if (findings.length === 0) {
            findingsCount.textContent = "0";
            findingsCount.classList.add("ct-badge--clean");
            resultsBody.innerHTML =
                '<div class="ct-finding ct-finding--info">' +
                '<div class="ct-finding-msg">No issues found. Code looks safe.</div>' +
                "</div>";
        } else {
            findingsCount.textContent = String(findings.length);
            findingsCount.classList.remove("ct-badge--clean");

            for (const finding of findings) {
                const severityClass =
                    finding.severity === "BLOCK"
                        ? ""
                        : finding.severity === "WARN"
                            ? "ct-finding--warn"
                            : "ct-finding--info";

                const suggestionHtml = finding.suggestion
                    ? '<div class="ct-finding-suggestion">\u2192 ' +
                    escapeHtml(finding.suggestion) +
                    "</div>"
                    : "";

                const findingEl = document.createElement("div");
                findingEl.className = "ct-finding " + severityClass;
                findingEl.innerHTML =
                    '<div class="ct-finding-rule">' +
                    escapeHtml(finding.rule_id) +
                    " \u00B7 " +
                    finding.severity +
                    "</div>" +
                    '<div class="ct-finding-msg">' +
                    escapeHtml(finding.message) +
                    "</div>" +
                    suggestionHtml;

                resultsBody.appendChild(findingEl);
            }
        }

        if (trustScore !== null && trustScore !== undefined) {
            trustScoreSection.style.display = "block";
            trustScoreValue.textContent = String(Math.round(trustScore));
            trustScoreFill.style.width = trustScore + "%";

            if (trustScore >= 80) {
                trustScoreValue.style.color = "var(--ct-success)";
            } else if (trustScore >= 50) {
                trustScoreValue.style.color = "var(--ct-warning)";
            } else {
                trustScoreValue.style.color = "var(--ct-danger)";
            }
        }
    }

    /**
     * Escape HTML entities for safe rendering.
     * @param {string} text
     * @returns {string}
     */
    function escapeHtml(text) {
        const div = document.createElement("div");
        div.appendChild(document.createTextNode(text));
        return div.innerHTML;
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

    /**
     * Send code to the CodeTrust API for scanning.
     * @param {string} code
     * @param {string} language
     * @param {string} scanType
     * @returns {Promise<{findings: Array, trust_score: number | null}>}
     */
    async function callScanApi(code, language, scanType) {
        const apiKey = await getApiKey();
        const url = API_BASE_URL + "/" + API_VERSION + "/scan";

        const response = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                ...(apiKey ? { "X-API-Key": apiKey } : {}),
            },
            body: JSON.stringify({
                code: code,
                language: language,
                scan_type: scanType,
            }),
        });

        if (!response.ok) {
            throw new Error("API error: " + response.status);
        }

        return response.json();
    }

    /**
     * Scan all code blocks found on the current page.
     */
    async function scanPageCode() {
        setStatus("scanning", "Scanning page...");
        btnScanPage.disabled = true;

        try {
            const [tab] = await chrome.tabs.query({
                active: true,
                currentWindow: true,
            });
            const results = await chrome.tabs.sendMessage(tab.id, {
                action: "extractCode",
            });

            if (!results || !results.codeBlocks || results.codeBlocks.length === 0) {
                setStatus("done", "No code found");
                renderResults([], null);
                return;
            }

            const allFindings = [];
            let totalScore = null;

            for (const block of results.codeBlocks) {
                try {
                    const scanResult = await callScanApi(
                        block.code,
                        block.language || "python",
                        "static"
                    );
                    if (scanResult.findings) {
                        allFindings.push(...scanResult.findings);
                    }
                    if (scanResult.trust_score !== undefined) {
                        totalScore = scanResult.trust_score;
                    }
                } catch (apiError) {
                    allFindings.push({
                        rule_id: "api_error",
                        severity: "WARN",
                        message: "Could not scan block: " + apiError.message,
                    });
                }
            }

            setStatus("done", allFindings.length + " issues found");
            renderResults(allFindings, totalScore);
        } catch (error) {
            setStatus("error", "Scan failed");
            renderResults(
                [
                    {
                        rule_id: "extension_error",
                        severity: "WARN",
                        message: error.message,
                    },
                ],
                null
            );
        } finally {
            btnScanPage.disabled = false;
        }
    }

    /**
     * Scan selected text on the current page.
     */
    async function scanSelection() {
        setStatus("scanning", "Scanning selection...");
        btnScanSelection.disabled = true;

        try {
            const [tab] = await chrome.tabs.query({
                active: true,
                currentWindow: true,
            });
            const results = await chrome.tabs.sendMessage(tab.id, {
                action: "getSelection",
            });

            if (!results || !results.selection) {
                setStatus("done", "No text selected");
                renderResults([], null);
                return;
            }

            const scanResult = await callScanApi(
                results.selection,
                results.language || "python",
                "static"
            );
            setStatus(
                "done",
                (scanResult.findings ? scanResult.findings.length : 0) + " issues found"
            );
            renderResults(
                scanResult.findings || [],
                scanResult.trust_score || null
            );
        } catch (error) {
            setStatus("error", "Scan failed");
            renderResults(
                [
                    {
                        rule_id: "extension_error",
                        severity: "WARN",
                        message: error.message,
                    },
                ],
                null
            );
        } finally {
            btnScanSelection.disabled = false;
        }
    }

    /**
     * Verify imports on the current page.
     */
    async function verifyImports() {
        setStatus("scanning", "Verifying imports...");
        btnVerifyImports.disabled = true;

        try {
            const [tab] = await chrome.tabs.query({
                active: true,
                currentWindow: true,
            });
            const results = await chrome.tabs.sendMessage(tab.id, {
                action: "extractCode",
            });

            if (!results || !results.codeBlocks || results.codeBlocks.length === 0) {
                setStatus("done", "No code found");
                renderResults([], null);
                return;
            }

            const allCode = results.codeBlocks.map((b) => b.code).join("\n");
            const scanResult = await callScanApi(allCode, "python", "deep");

            const importFindings = (scanResult.findings || []).filter(
                (f) =>
                    f.rule_id.includes("import") ||
                    f.rule_id.includes("hallucin") ||
                    f.rule_id.includes("registry")
            );

            setStatus("done", importFindings.length + " import issues");
            renderResults(importFindings, scanResult.trust_score || null);
        } catch (error) {
            setStatus("error", "Verification failed");
            renderResults(
                [
                    {
                        rule_id: "extension_error",
                        severity: "WARN",
                        message: error.message,
                    },
                ],
                null
            );
        } finally {
            btnVerifyImports.disabled = false;
        }
    }
});
