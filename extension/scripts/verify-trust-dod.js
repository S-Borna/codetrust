const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const EXT_ROOT = path.resolve(__dirname, "..");
const REPO_ROOT = path.resolve(EXT_ROOT, "..");
const MCP_INJECTION_PATH = path.resolve(EXT_ROOT, "src", "mcp-config-injection.ts");
const MCP_TEST_PATH = path.resolve(EXT_ROOT, "src", "test", "suite", "mcp-config-injection.test.ts");
const RELEASE_GUARD_PATH = path.resolve(EXT_ROOT, "scripts", "check-release-sync.js");
const PACKAGE_JSON_PATH = path.resolve(EXT_ROOT, "package.json");
const GATEWAY_SERVER_PATH = path.resolve(REPO_ROOT, "src", "gateway", "server.py");
const UNIVERSAL_INSTRUCTIONS_PATH = path.resolve(EXT_ROOT, "src", "universal-instructions.ts");
const EXTENSION_SOURCE_PATH = path.resolve(EXT_ROOT, "src", "extension.ts");

function readText(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function runCommand(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
  });
  return {
    ok: result.status === 0,
    code: result.status,
    stdout: result.stdout || "",
    stderr: result.stderr || "",
  };
}

function passFailRow(id, ok, detail) {
  const status = ok ? "PASS" : "FAIL";
  return `${id}: ${status} - ${detail}`;
}

function resolveNpmTestResult() {
  const releaseSmokeTestsPassed = process.env.RELEASE_SMOKE_EXTENSION_TESTS_PASSED === "1";
  if (releaseSmokeTestsPassed) {
    return {
      ok: true,
      code: 0,
      stdout: "",
      stderr: "",
      skipped: true,
      detail: "SKIP (reusing prior release-smoke tests gate)",
    };
  }

  const result = runCommand("npm", ["run", "test", "--", "--runInBand"], EXT_ROOT);
  return {
    ...result,
    skipped: false,
    detail: result.ok ? "PASS" : "FAIL",
  };
}

function checkDOD() {
  const mcpInjection = readText(MCP_INJECTION_PATH);
  const mcpTest = readText(MCP_TEST_PATH);
  const releaseGuard = readText(RELEASE_GUARD_PATH);
  const pkg = JSON.parse(readText(PACKAGE_JSON_PATH));
  const gatewayServer = readText(GATEWAY_SERVER_PATH);
  const universalInstructions = readText(UNIVERSAL_INSTRUCTIONS_PATH);
  const extensionSource = readText(EXTENSION_SOURCE_PATH);

  const checks = [];

  const hasWorkspaceTarget =
    mcpInjection.includes(".vscode") && mcpInjection.includes("mcp.json");
  checks.push({
    id: "DOD-T1",
    ok: hasWorkspaceTarget,
    detail: "workspace MCP target exists in injector",
  });

  const requiredGatewayTools = [
    "codetrust_validate_command",
    "codetrust_validate_file_write",
    "codetrust_validate_file_delete",
    "codetrust_validate_package",
    "codetrust_run_in_terminal",
  ];
  const hasRuntimeGatewayRegistration =
    mcpInjection.includes("GATEWAY_SERVER_NAME") &&
    mcpInjection.includes("codetrust-gateway");
  const hasRequiredGatewayTools = requiredGatewayTools.every((toolName) =>
    gatewayServer.includes(`name=\"${toolName}\"`),
  );
  const hasGatewayToolClaim =
    pkg.description.includes("AI Governance Gateway") &&
    hasRuntimeGatewayRegistration &&
    hasRequiredGatewayTools;
  checks.push({
    id: "DOD-T2",
    ok: hasGatewayToolClaim,
    detail: "gateway runtime registration and required enforcement tools exist",
  });

  const hasCopilotClaimParityGate =
    releaseGuard.includes("ensureCopilotClaimMatchesInjection") &&
    releaseGuard.includes(".vscode") &&
    releaseGuard.includes("mcp.json");
  checks.push({
    id: "DOD-T3",
    ok: hasCopilotClaimParityGate,
    detail: "claim/implementation parity guard is active",
  });

  const hasRegressionTest =
    mcpTest.includes("builds workspace mcp paths deterministically") &&
    mcpTest.includes("includes all workspace folders as mcp targets");
  checks.push({
    id: "DOD-T4",
    ok: hasRegressionTest && hasCopilotClaimParityGate,
    detail: "regression coverage + release parity guard present",
  });

  const hasDeterministicHelper =
    mcpInjection.includes("buildWorkspaceMcpTargetPathsForTest") &&
    mcpInjection.includes("listMcpTargetPathsForTest");
  checks.push({
    id: "DOD-T5",
    ok: hasDeterministicHelper,
    detail: "deterministic and testable MCP path contract exists",
  });

  const forbiddenVaguePhrases = [
    "CodeTrust MCP tools are unavailable, proceeding with extra caution",
    "extra caution",
  ];
  const extensionSrcRoot = path.resolve(EXT_ROOT, "src");
  const sourceFiles = [];

  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile() && full.endsWith(".ts")) {
        sourceFiles.push(full);
      }
    }
  }

  walk(extensionSrcRoot);
  let hasVagueFallback = false;
  for (const file of sourceFiles) {
    const content = readText(file);
    if (forbiddenVaguePhrases.some((phrase) => content.includes(phrase))) {
      hasVagueFallback = true;
      break;
    }
  }

  checks.push({
    id: "DOD-T6",
    ok: !hasVagueFallback,
    detail: "no known vague trust fallback message in extension source",
  });

  const hasWindsurfTarget =
    universalInstructions.includes("Windsurf (~/.codeium/windsurf/memories/global_rules.md)") &&
    universalInstructions.includes(".codeium") &&
    universalInstructions.includes("watchForGovernanceDisruption");
  checks.push({
    id: "DOD-T7",
    ok: hasWindsurfTarget,
    detail: "Windsurf global-rule injection target + disruption watcher coverage exists",
  });

  const hasCopilotGlobalInjection =
    extensionSource.includes("injectCopilotInstructions") &&
    extensionSource.includes("github.copilot.chat") &&
    extensionSource.includes("codeGeneration.instructions") &&
    extensionSource.includes("vscode.ConfigurationTarget.Global");
  checks.push({
    id: "DOD-T8",
    ok: hasCopilotGlobalInjection,
    detail: "Copilot rules are injected via global settings scope (clean-profile safe)",
  });

  const hasWorkspaceVarGuard =
    mcpInjection.includes("const VSCODE_WORKSPACE_VAR = \"${workspaceFolder}\"") &&
    mcpInjection.includes("Only inject ${workspaceFolder} for workspace-level targets") &&
    mcpInjection.includes("Global (User/mcp.json)") &&
    mcpInjection.includes("serversKey: \"servers\"");
  checks.push({
    id: "DOD-T9",
    ok: hasWorkspaceVarGuard,
    detail: "global VS Code MCP targets enforce 'servers' key + workspaceFolder guardrails",
  });

  const npmTest = resolveNpmTestResult();
  const releaseSync = runCommand("node", ["./scripts/check-release-sync.js"], EXT_ROOT);

  return {
    checks,
    npmTest,
    releaseSync,
  };
}

function main() {
  const { checks, npmTest, releaseSync } = checkDOD();

  process.stdout.write("CodeTrust Trust DOD Verification\n");
  process.stdout.write("================================\n");
  for (const check of checks) {
    process.stdout.write(`${passFailRow(check.id, check.ok, check.detail)}\n`);
  }

  process.stdout.write(`npm run test: ${npmTest.detail}\n`);
  process.stdout.write(`node ./scripts/check-release-sync.js: ${releaseSync.ok ? "PASS" : "FAIL"}\n`);

  const allChecksPass = checks.every((check) => check.ok) && npmTest.ok && releaseSync.ok;

  if (!allChecksPass) {
    process.stdout.write("\nTrust DOD verification failed.\n");
    if (!npmTest.ok) {
      process.stdout.write("\n--- npm run test output (tail) ---\n");
      process.stdout.write((npmTest.stdout + npmTest.stderr).slice(-4000));
      process.stdout.write("\n");
    }
    if (!releaseSync.ok) {
      process.stdout.write("\n--- release sync output ---\n");
      process.stdout.write(releaseSync.stdout + releaseSync.stderr);
      process.stdout.write("\n");
    }
    process.exit(1);
  }

  process.stdout.write("\nAll Trust DOD checks passed.\n");
}

main();
