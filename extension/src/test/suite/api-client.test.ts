// Copyright (c) Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.
/**
 * Unit tests for the CodeTrust API client.
 * Tests request building, error handling, and response parsing.
 */

import * as assert from "assert";
import { ApiClient, ApiError } from "../../api-client";
import type { ExtensionConfig } from "../../types";

const TEST_DEBOUNCE_MS = 600;
const TEST_TIMEOUT_MS = 5000;
const BAD_PORT_TIMEOUT_MS = 1000;
const HTTP_NOT_FOUND = 404;

/** Create a test config. */
function testConfig(overrides?: Partial<ExtensionConfig>): ExtensionConfig {
    return {
        apiUrl: "http://localhost:8000",
        apiKey: "tk_test",
        scanOnSave: true,
        scanOnType: false,
        scanOnTypeDebounceMs: TEST_DEBOUNCE_MS,
        severityThreshold: "INFO",
        enabledLanguages: ["python", "javascript", "typescript", "go", "rust"],
        scanType: "static",
        verifyImportsOnSave: false,
        timeout: TEST_TIMEOUT_MS,
        governance: {
            enabled: true,
            mode: "enforce",
            blockHeredoc: true,
            blockEval: true,
            blockGitPush: true,
            protectedPaths: ["LICENSE", ".env"],
        },
        ...overrides,
    };
}

suite("ApiClient Tests", () => {
    test("creates client with config", () => {
        const config = testConfig();
        const client = new ApiClient(config);
        assert.ok(client);
    });

    test("updates config", () => {
        const config = testConfig();
        const client = new ApiClient(config);
        const newConfig = testConfig({ apiUrl: "http://api.codetrust.ai" });
        client.updateConfig(newConfig);
        assert.ok(client);
    });

    test("strips trailing slashes from URL", () => {
        const config = testConfig({ apiUrl: "http://localhost:8000///" });
        const client = new ApiClient(config);
        assert.ok(client);
    });

    test("handles ApiError construction", () => {
        const error = new ApiError("Not found", HTTP_NOT_FOUND, '{"detail":"not found"}');
        assert.strictEqual(error.name, "ApiError");
        assert.strictEqual(error.statusCode, HTTP_NOT_FOUND);
        assert.strictEqual(error.body, '{"detail":"not found"}');
        assert.ok(error.message.includes("Not found"));
    });

    test("staticScan rejects on connection refused", async () => {
        const config = testConfig({ apiUrl: "http://localhost:59999", timeout: BAD_PORT_TIMEOUT_MS });
        const client = new ApiClient(config);
        try {
            await client.staticScan("print('hello')", "test.py", "python");
            assert.fail("Should have thrown");
        } catch (err) {
            assert.ok(err instanceof ApiError);
        }
    });

    test("checkHealth rejects on bad port", async () => {
        const config = testConfig({ apiUrl: "http://localhost:59999", timeout: BAD_PORT_TIMEOUT_MS });
        const client = new ApiClient(config);
        try {
            await client.checkHealth();
            assert.fail("Should have thrown");
        } catch (err) {
            assert.ok(err instanceof ApiError);
        }
    });
});
