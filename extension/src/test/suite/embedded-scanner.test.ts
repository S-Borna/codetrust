// Copyright (c) Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.
/**
 * Unit tests for the embedded offline scanner.
 * Verifies all 49 rules: 40 regex + 9 file-level checks.
 */

import * as assert from "assert";
import { scanCodeOffline } from "../../embedded-scanner";

suite("Embedded Scanner Tests", () => {
    // ───────────────────────────────────────────────────────────
    //  REGEX RULE TESTS (40 rules)
    // ───────────────────────────────────────────────────────────

    suite("BLOCK rules", () => {
        test("detects heredoc", () => {
            const result = scanCodeOffline("cat <" + "<EOF\nhello\nEOF", "script.sh");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("heredoc"), `Expected heredoc, got: ${ids}`);
        });

        test("detects hardcoded secret", () => {
            const result = scanCodeOffline('API_' + 'KEY = "sk-1234567890abcdef"', "config.py");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("hardcoded_secret"), `Expected hardcoded_secret, got: ${ids}`);
        });

        test("detects eval/exec", () => {
            const result = scanCodeOffline("result = " + "ev" + "al(user_input)", "app.py");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("eval_exec"), `Expected eval_exec, got: ${ids}`);
        });

        test("detects wildcard import", () => {
            const result = scanCodeOffline("from os " + "import " + "*", "app.py");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("wildcard_import"), `Expected wildcard_import, got: ${ids}`);
        });

        test("detects pickle load", () => {
            const result = scanCodeOffline("data = pickle.load(f)", "app.py");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("pickle_load"), `Expected pickle_load, got: ${ids}`);
        });
    });

    suite("WARN rules", () => {
        test("detects TODO marker", () => {
            const result = scanCodeOffline("# " + "TO" + "DO: fix this", "app.py");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("todo_marker"), `Expected todo_marker, got: ${ids}`);
        });

        test("detects console logger call", () => {
            const result = scanCodeOffline("console." + "log('debug')", "app.js");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("console_log"), `Expected console_log, got: ${ids}`);
        });

        test("detects debug mode", () => {
            const result = scanCodeOffline('DEBUG = "true"', "app.py");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("debug_mode_enabled"), `Expected debug_mode_enabled, got: ${ids}`);
        });

        test("detects suppress_lint with noqa", () => {
            const result = scanCodeOffline("x = 1  # noqa", "app.py");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("suppress_lint"), `Expected suppress_lint, got: ${ids}`);
        });
    });

    suite("INFO rules", () => {
        test("detects broad except", () => {
            const result = scanCodeOffline("except Exception:", "app.py");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("broad_except"), `Expected broad_except, got: ${ids}`);
        });

        test("detects untyped function", () => {
            const result = scanCodeOffline("def foo(x):\n    return x", "app.py");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("untyped_function"), `Expected untyped_function, got: ${ids}`);
        });
    });

    suite("SQL rules", () => {
        test("detects SELECT *", () => {
            const result = scanCodeOffline("SELECT * FROM users;", "query.sql");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("sql_select_star"), `Expected sql_select_star, got: ${ids}`);
        });

        test("detects DROP TABLE", () => {
            const result = scanCodeOffline("DROP TABLE users;", "query.sql");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("sql_drop_table"), `Expected sql_drop_table, got: ${ids}`);
        });
    });

    suite("Docker rules", () => {
        test("detects latest tag", () => {
            const result = scanCodeOffline("FROM python:latest", "Dockerfile");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("docker_latest_tag"), `Expected docker_latest_tag, got: ${ids}`);
        });
    });

    // ───────────────────────────────────────────────────────────
    //  FILE-LEVEL CHECKS (9 special_handler rules)
    // ───────────────────────────────────────────────────────────

    suite("except_swallow", () => {
        test("flags except with bare pass", () => {
            const code = "try:\n    risky()\nexcept:\n    pass\n";
            const result = scanCodeOffline(code, "app.py");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("except_swallow"), `Expected except_swallow, got: ${ids}`);
        });

        test("flags except with ellipsis", () => {
            const code = "try:\n    risky()\nexcept Exception:\n    ...\n";
            const result = scanCodeOffline(code, "app.py");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("except_swallow"), `Expected except_swallow, got: ${ids}`);
        });

        test("passes when except has real handler", () => {
            const code = "try:\n    risky()\nexcept Exception as e:\n    logger.error(e)\n";
            const result = scanCodeOffline(code, "app.py");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(!ids.includes("except_swallow"), `Should NOT flag except_swallow, got: ${ids}`);
        });
    });

    suite("sleep_no_context", () => {
        test("flags sleep without comment", () => {
            const code = "import time\ntime.sleep(5)\n";
            const result = scanCodeOffline(code, "app.py");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("sleep_no_context"), `Expected sleep_no_context, got: ${ids}`);
        });

        test("passes when sleep has preceding comment", () => {
            const code = "import time\n# Wait for service startup\ntime.sleep(5)\n";
            const result = scanCodeOffline(code, "app.py");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(!ids.includes("sleep_no_context"), `Should NOT flag sleep_no_context`);
        });
    });

    suite("long_function", () => {
        test("flags function over 40 lines", () => {
            const bodyLines = Array.from({ length: 45 }, (_, i) => `    x = ${i}`);
            const code = `def big_function():\n${bodyLines.join("\n")}\n`;
            const result = scanCodeOffline(code, "app.py");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("long_function"), `Expected long_function, got: ${ids}`);
        });

        test("passes for short function", () => {
            const code = "def small():\n    return 1\n";
            const result = scanCodeOffline(code, "app.py");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(!ids.includes("long_function"), `Should NOT flag long_function`);
        });
    });

    suite("connection_no_timeout", () => {
        test("flags Client() without timeout", () => {
            const code = "import httpx\nclient = httpx.Client()\n";
            const result = scanCodeOffline(code, "app.py");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("connection_no_timeout"), `Expected connection_no_timeout, got: ${ids}`);
        });

        test("passes when timeout is present", () => {
            const code = "import httpx\nclient = httpx.Client(timeout=30)\n";
            const result = scanCodeOffline(code, "app.py");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(!ids.includes("connection_no_timeout"), `Should NOT flag connection_no_timeout`);
        });
    });

    suite("dockerfile_no_healthcheck", () => {
        test("flags Dockerfile with CMD but no HEALTHCHECK", () => {
            const code = "FROM python:3.12\nCMD ['python', 'app.py']\n";
            const result = scanCodeOffline(code, "Dockerfile");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("dockerfile_no_healthcheck"), `Expected dockerfile_no_healthcheck, got: ${ids}`);
        });

        test("passes when HEALTHCHECK is present", () => {
            const code = "FROM python:3.12\nHEALTHCHECK CMD curl -f http://localhost/\nCMD ['python', 'app.py']\n";
            const result = scanCodeOffline(code, "Dockerfile");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(!ids.includes("dockerfile_no_healthcheck"), `Should NOT flag dockerfile_no_healthcheck`);
        });
    });

    suite("docker_root_user", () => {
        test("flags Dockerfile running as root", () => {
            const code = "FROM python:3.12\nCMD ['python', 'app.py']\n";
            const result = scanCodeOffline(code, "Dockerfile");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("docker_root_user"), `Expected docker_root_user, got: ${ids}`);
        });

        test("passes when USER is set", () => {
            const code = "FROM python:3.12\nUSER nonroot\nCMD ['python', 'app.py']\n";
            const result = scanCodeOffline(code, "Dockerfile");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(!ids.includes("docker_root_user"), `Should NOT flag docker_root_user`);
        });
    });

    suite("docker_no_workdir", () => {
        test("flags Dockerfile without WORKDIR", () => {
            const code = "FROM python:3.12\nCMD ['python', 'app.py']\n";
            const result = scanCodeOffline(code, "Dockerfile");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("docker_no_workdir"), `Expected docker_no_workdir, got: ${ids}`);
        });

        test("passes when WORKDIR is set", () => {
            const code = "FROM python:3.12\nWORKDIR /app\nCMD ['python', 'app.py']\n";
            const result = scanCodeOffline(code, "Dockerfile");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(!ids.includes("docker_no_workdir"), `Should NOT flag docker_no_workdir`);
        });
    });

    suite("compose_no_healthcheck", () => {
        test("flags compose service without healthcheck", () => {
            const code = "services:\n  web:\n    image: nginx:latest\n    ports:\n      - '80:80'\n";
            const result = scanCodeOffline(code, "docker-compose.yml");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("compose_no_healthcheck"), `Expected compose_no_healthcheck, got: ${ids}`);
        });

        test("passes when healthcheck is present", () => {
            const code = "services:\n  web:\n    image: nginx:latest\n    healthcheck:\n      test: curl -f http://localhost/\n";
            const result = scanCodeOffline(code, "docker-compose.yml");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(!ids.includes("compose_no_healthcheck"), `Should NOT flag compose_no_healthcheck`);
        });
    });

    suite("ci_no_timeout", () => {
        test("flags CI job without timeout-minutes", () => {
            const code = "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";
            const result = scanCodeOffline(code, ".github/workflows/ci.yml");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(ids.includes("ci_no_timeout"), `Expected ci_no_timeout, got: ${ids}`);
        });

        test("passes when timeout-minutes is set", () => {
            const code = "jobs:\n  build:\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n    steps:\n      - run: echo hi\n";
            const result = scanCodeOffline(code, ".github/workflows/ci.yml");
            const ids = result.findings.map((f) => f.rule_id);
            assert.ok(!ids.includes("ci_no_timeout"), `Should NOT flag ci_no_timeout`);
        });
    });

    // ───────────────────────────────────────────────────────────
    //  VERDICT LOGIC
    // ───────────────────────────────────────────────────────────

    suite("verdict", () => {
        test("returns PASS for clean code", () => {
            const result = scanCodeOffline("x: int = 1\n", "app.py");
            assert.strictEqual(result.verdict, "PASS");
        });

        test("returns BLOCK when BLOCK findings exist", () => {
            const result = scanCodeOffline("result = " + "ev" + "al(input())", "app.py");
            assert.strictEqual(result.verdict, "BLOCK");
        });

        test("returns WARN when only WARN findings exist", () => {
            const result = scanCodeOffline("# " + "TO" + "DO: fix this later", "app.py");
            assert.strictEqual(result.verdict, "WARN");
        });

        test("counts findings correctly", () => {
            const result = scanCodeOffline("result = " + "ev" + "al(input())\n# " + "TO" + "DO: fix", "app.py");
            assert.ok(result.total_findings >= 2);
            assert.ok(result.blocks >= 1);
        });
    });
});
