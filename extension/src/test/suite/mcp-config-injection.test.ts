// Copyright (c) Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.
import * as assert from "assert";
import * as path from "path";
import * as vscode from "vscode";

import {
    buildWorkspaceMcpTargetPathsForTest,
    listMcpTargetPathsForTest,
    verifyMcpServerHealth,
} from "../../mcp-config-injection";

suite("MCP config injection contract", () => {
    test("builds workspace mcp paths deterministically", () => {
        const workspacePaths = [
            "/tmp/workspace-a",
            "/tmp/workspace-b",
        ];

        const targets = buildWorkspaceMcpTargetPathsForTest(workspacePaths);

        assert.deepStrictEqual(targets, [
            path.join("/tmp/workspace-a", ".vscode", "mcp.json"),
            path.join("/tmp/workspace-b", ".vscode", "mcp.json"),
        ]);
    });

    test("includes all workspace folders as mcp targets", () => {
        const workspaceFolders = vscode.workspace.workspaceFolders ?? [];
        const targets = listMcpTargetPathsForTest();

        for (const folder of workspaceFolders) {
            const expectedPath = path.join(folder.uri.fsPath, ".vscode", "mcp.json");
            assert.ok(
                targets.includes(expectedPath),
                `Expected MCP target for workspace folder: ${folder.uri.fsPath}`,
            );
        }
    });

    test("verifyMcpServerHealth returns structured result", () => {
        const outputChannel = {
            appendLine: (): void => { },
        } as unknown as vscode.OutputChannel;

        const result = verifyMcpServerHealth(outputChannel);

        assert.strictEqual(typeof result.healthy, "boolean");
        assert.ok(Array.isArray(result.issues));
        for (const issue of result.issues) {
            assert.strictEqual(typeof issue.target, "string");
            assert.strictEqual(typeof issue.problem, "string");
            assert.strictEqual(typeof issue.fix, "string");
        }

    });
});
