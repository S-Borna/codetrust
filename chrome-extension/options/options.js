// Copyright (c) Said Borna. All rights reserved.

const DEFAULT_API_URL = "https://api.codetrust.ai";
const SAVED_INDICATOR_TIMEOUT_MS = 2000;

document.addEventListener("DOMContentLoaded", () => {
    const apiKeyInput = document.getElementById("api-key");
    const apiUrlInput = document.getElementById("api-url");
    const autoScanInput = document.getElementById("auto-scan");
    const showNotificationsInput = document.getElementById("show-notifications");
    const verifyImportsInput = document.getElementById("verify-imports");
    const btnSave = document.getElementById("btn-save");
    const savedIndicator = document.getElementById("saved-indicator");

    // Load saved settings
    chrome.storage.sync.get(
        {
            codetrust_api_key: "",
            codetrust_api_url: DEFAULT_API_URL,
            codetrust_auto_scan: true,
            codetrust_show_notifications: true,
            codetrust_verify_imports: false,
        },
        (items) => {
            apiKeyInput.value = items.codetrust_api_key;
            apiUrlInput.value = items.codetrust_api_url;
            autoScanInput.checked = items.codetrust_auto_scan;
            showNotificationsInput.checked = items.codetrust_show_notifications;
            verifyImportsInput.checked = items.codetrust_verify_imports;
        }
    );

    btnSave.addEventListener("click", () => {
        chrome.storage.sync.set(
            {
                codetrust_api_key: apiKeyInput.value.trim(),
                codetrust_api_url: apiUrlInput.value.trim() || DEFAULT_API_URL,
                codetrust_auto_scan: autoScanInput.checked,
                codetrust_show_notifications: showNotificationsInput.checked,
                codetrust_verify_imports: verifyImportsInput.checked,
            },
            () => {
                savedIndicator.classList.add("ct-saved--visible");
                setTimeout(() => {
                    savedIndicator.classList.remove("ct-saved--visible");
                }, SAVED_INDICATOR_TIMEOUT_MS);
            }
        );
    });
});
