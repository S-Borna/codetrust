// Copyright (c) Said Borna. All rights reserved.

/**
 * Language detection patterns for code blocks.
 * @type {Record<string, RegExp>}
 */
const LANGUAGE_PATTERNS = {
    python: /\b(import\s+\w+|from\s+\w+\s+import|def\s+\w+|class\s+\w+|if\s+__name__|print\()/,
    javascript: /\b(const\s+\w+|let\s+\w+|var\s+\w+|function\s+\w+|=>|require\(|module\.exports)/,
    typescript: /\b(interface\s+\w+|type\s+\w+|:\s*(string|number|boolean)|as\s+\w+|export\s+default)/,
    go: /\b(func\s+\w+|package\s+\w+|import\s+\(|fmt\.|:=)/,
    rust: /\b(fn\s+\w+|let\s+mut|impl\s+\w+|use\s+\w+::|pub\s+fn)/,
    java: /\b(public\s+class|private\s+|protected\s+|System\.out|void\s+main)/,
    shell: /\b(echo\s+|export\s+\w+=|if\s+\[\[)/,
    sql: /\b(SELECT\s+|INSERT\s+INTO|UPDATE\s+|DELETE\s+FROM|CREATE\s+TABLE)/i,
    yaml: /^\s*\w+:\s*$/m,
    dockerfile: /^FROM\s+\w+/m,
};

/**
 * Code block selectors for supported platforms.
 * @type {Array<string>}
 */
const CODE_SELECTORS = [
    "pre code",
    ".highlight pre",
    ".code-area pre",
    ".blob-code-content",
    ".CodeMirror-code",
    ".monaco-editor .view-lines",
    "code.highlight",
    ".s-code-block",
    ".prism-code",
    "pre.notranslate",
    ".markdown-body pre",
];

/**
 * Detect the programming language of a code block.
 * @param {string} code
 * @param {Element} element
 * @returns {string}
 */
function detectLanguage(code, element) {
    const classNames = (element.className || "") + " " + (element.parentElement?.className || "");
    const classMatch = classNames.match(/(?:language-|lang-|highlight-)(\w+)/);
    if (classMatch) {
        return classMatch[1].toLowerCase();
    }

    for (const [lang, pattern] of Object.entries(LANGUAGE_PATTERNS)) {
        if (pattern.test(code)) {
            return lang;
        }
    }

    return "python";
}

/**
 * Extract all code blocks from the current page.
 * @returns {Array<{code: string, language: string}>}
 */
function extractCodeBlocks() {
    const codeBlocks = [];
    const seen = new Set();

    for (const selector of CODE_SELECTORS) {
        const elements = document.querySelectorAll(selector);
        for (const element of elements) {
            const code = element.textContent?.trim();
            if (!code || code.length < 10 || seen.has(code)) {
                continue;
            }
            seen.add(code);

            codeBlocks.push({
                code: code,
                language: detectLanguage(code, element),
            });
        }
    }

    return codeBlocks;
}

/**
 * Get the currently selected text and detect its language.
 * @returns {{selection: string, language: string} | null}
 */
function getSelectedText() {
    const selection = window.getSelection()?.toString()?.trim();
    if (!selection || selection.length < 5) {
        return null;
    }

    let language = "python";
    for (const [lang, pattern] of Object.entries(LANGUAGE_PATTERNS)) {
        if (pattern.test(selection)) {
            language = lang;
            break;
        }
    }

    return { selection, language };
}

/**
 * Display inline results overlay for findings.
 * @param {Array<{rule_id: string, severity: string, message: string, suggestion?: string}>} findings
 * @param {number | null} trustScore
 */
function showResultsOverlay(findings, trustScore) {
    const existing = document.getElementById("codetrust-overlay");
    if (existing) {
        existing.remove();
    }

    const overlay = document.createElement("div");
    overlay.id = "codetrust-overlay";
    overlay.className = "ct-overlay";

    const header = document.createElement("div");
    header.className = "ct-overlay-header";
    header.innerHTML =
        '<span class="ct-overlay-title">CodeTrust Scan Results</span>' +
        '<button class="ct-overlay-close" id="ct-close-overlay">\u00D7</button>';
    overlay.appendChild(header);

    if (trustScore !== null && trustScore !== undefined) {
        const scoreEl = document.createElement("div");
        scoreEl.className = "ct-overlay-score";
        scoreEl.textContent = "Trust Score: " + Math.round(trustScore) + "/100";
        overlay.appendChild(scoreEl);
    }

    const body = document.createElement("div");
    body.className = "ct-overlay-body";

    if (findings.length === 0) {
        body.innerHTML = '<div class="ct-overlay-clean">\u2713 No issues found</div>';
    } else {
        for (const finding of findings) {
            const el = document.createElement("div");
            el.className = "ct-overlay-finding ct-overlay-finding--" + finding.severity.toLowerCase();
            el.innerHTML =
                '<span class="ct-overlay-severity">' + finding.severity + "</span> " +
                '<span class="ct-overlay-rule">' + finding.rule_id + "</span>" +
                '<div class="ct-overlay-msg">' + escapeHtml(finding.message) + "</div>";
            if (finding.suggestion) {
                el.innerHTML += '<div class="ct-overlay-suggestion">\u2192 ' + escapeHtml(finding.suggestion) + "</div>";
            }
            body.appendChild(el);
        }
    }

    overlay.appendChild(body);
    document.body.appendChild(overlay);

    document.getElementById("ct-close-overlay")?.addEventListener("click", () => {
        overlay.remove();
    });

    setTimeout(() => {
        overlay.remove();
    }, 30000);
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
 * Listen for messages from popup or background script.
 */
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.action === "extractCode") {
        const codeBlocks = extractCodeBlocks();
        sendResponse({ codeBlocks });
    } else if (message.action === "getSelection") {
        const result = getSelectedText();
        sendResponse(result);
    } else if (message.action === "showResults") {
        showResultsOverlay(message.findings || [], message.trustScore || null);
        sendResponse({ ok: true });
    }
    return true;
});
