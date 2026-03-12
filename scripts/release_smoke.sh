#!/usr/bin/env bash
# Copyright (c) Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
EXT_DIR="$ROOT_DIR/extension"

if [[ "${CI:-}" == "true" ]]; then
    AUTO_FIX_MCP="${AUTO_FIX_MCP:-0}"
else
    AUTO_FIX_MCP="${AUTO_FIX_MCP:-1}"
fi

PASS_COUNT=0
FAIL_COUNT=0

log_step() {
    printf "\n[release-smoke] %s\n" "$1"
}

mark_pass() {
    printf "[release-smoke] PASS: %s\n" "$1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

mark_fail() {
    printf "[release-smoke] FAIL: %s\n" "$1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

run_cmd() {
    local label="$1"
    shift
    if "$@"; then
        mark_pass "$label"
    else
        mark_fail "$label"
    fi
}

run_headless_or_plain() {
    local label="$1"
    shift
    if command -v xvfb-run >/dev/null 2>&1; then
        run_cmd "$label" xvfb-run -a "$@"
    else
        run_cmd "$label" "$@"
    fi
}

check_repo_venv_binaries() {
    local venv_dir="$ROOT_DIR/.venv/bin"
    if [[ ! -d "$venv_dir" ]]; then
        printf "[release-smoke] INFO: .venv/bin not found, skipping local binary checks\n"
        return 0
    fi

    if [[ -x "$venv_dir/codetrust-mcp" ]]; then
        mark_pass "repo venv has executable codetrust-mcp"
    else
        mark_fail "repo venv missing executable codetrust-mcp"
    fi

    if [[ -x "$venv_dir/codetrust-gateway-mcp" ]]; then
        mark_pass "repo venv has executable codetrust-gateway-mcp"
    else
        mark_fail "repo venv missing executable codetrust-gateway-mcp"
    fi
}

check_mcp_configs() {
    local checker
    checker='const fs=require("fs");const path=require("path");const emit=(line)=>{process.stdout.write(line+"\\n");};const root=process.env.RELEASE_SMOKE_ROOT||"";const autoFix=process.env.AUTO_FIX_MCP==="1";const home=process.env.HOME||"";const targets=[];if(process.platform==="darwin"){targets.push({file:path.join(home,"Library","Application Support","Code","User","mcp.json"),key:"servers"});targets.push({file:path.join(home,"Library","Application Support","Claude","claude_desktop_config.json"),key:"mcpServers"});}else if(process.platform==="linux"){targets.push({file:path.join(home,".config","Code","User","mcp.json"),key:"servers"});}targets.push({file:path.join(home,".claude","mcp.json"),key:"mcpServers"});targets.push({file:path.join(home,".cursor","mcp.json"),key:"mcpServers"});const required=["codetrust","codetrust-gateway"];const commands={codetrust:path.join(root,".venv","bin","codetrust-mcp"),"codetrust-gateway":path.join(root,".venv","bin","codetrust-gateway-mcp")};const cmdResolvable=(cmd)=>{if(path.isAbsolute(cmd)){return fs.existsSync(cmd);}if(cmd==="uvx"){return (process.env.PATH||"").split(path.delimiter).some(p=>fs.existsSync(path.join(p,"uvx")));}return (process.env.PATH||"").split(path.delimiter).some(p=>fs.existsSync(path.join(p,cmd)));};let fail=0;for(const target of targets){const file=target.file;const key=target.key;if(!fs.existsSync(file)){if(autoFix){const dir=path.dirname(file);if(!fs.existsSync(dir)){emit(`[release-smoke] INFO: MCP config directory not found, skipping ${file}`);continue;}const cfg={};cfg[key]={};for(const name of required){cfg[key][name]={command:commands[name],_injectedBy:"release-smoke-autofix"};}fs.writeFileSync(file,JSON.stringify(cfg,null,2)+"\\n","utf8");emit(`[release-smoke] PASS: created and populated ${file}`);continue;}emit(`[release-smoke] INFO: MCP config not found, skipping ${file}`);continue;}let data={};try{data=JSON.parse(fs.readFileSync(file,"utf8"));}catch{emit(`[release-smoke] FAIL: Invalid JSON in ${file}`);fail++;continue;}if(!data[key]||typeof data[key]!=="object"){data[key]={};}const bucket=data[key];let modified=false;for(const name of required){const entry=bucket[name];if(!entry){if(autoFix){bucket[name]={command:commands[name],_injectedBy:"release-smoke-autofix"};modified=true;emit(`[release-smoke] PASS: autofixed missing ${name} in ${file}`);continue;}emit(`[release-smoke] FAIL: ${name} missing in ${file}`);fail++;continue;}const cmd=String(entry.command||"");if(!cmd){if(autoFix){entry.command=commands[name];modified=true;emit(`[release-smoke] PASS: autofixed empty command for ${name} in ${file}`);continue;}emit(`[release-smoke] FAIL: ${name} command empty in ${file}`);fail++;continue;}if(!cmdResolvable(cmd)){if(autoFix){entry.command=commands[name];modified=true;emit(`[release-smoke] PASS: autofixed unresolved command for ${name} in ${file}`);continue;}emit(`[release-smoke] FAIL: ${name} command not resolvable in ${file}: ${cmd}`);fail++;continue;}emit(`[release-smoke] PASS: ${name} command resolvable in ${file}: ${cmd}`);}if(modified){fs.writeFileSync(file,JSON.stringify(data,null,2)+"\\n","utf8");}}process.exit(fail===0?0:1);'
    if RELEASE_SMOKE_ROOT="$ROOT_DIR" AUTO_FIX_MCP="$AUTO_FIX_MCP" node -e "$checker"; then
        mark_pass "MCP config command resolvability checks"
    else
        mark_fail "MCP config command resolvability checks"
    fi
}

log_step "Installing extension dependencies"
run_cmd "npm ci (extension)" bash -lc "cd '$EXT_DIR' && npm ci"

log_step "Running extension build and quality gates"
run_cmd "compile" bash -lc "cd '$EXT_DIR' && npm run compile"
run_cmd "lint" bash -lc "cd '$EXT_DIR' && npm run lint"
run_headless_or_plain "tests" bash -lc "cd '$EXT_DIR' && npm test -- --runInBand"
run_cmd "trust DOD gate" bash -lc "cd '$EXT_DIR' && npm run verify:trust-dod"

log_step "Checking MCP startup prerequisites"
if [[ "$AUTO_FIX_MCP" == "1" ]]; then
    printf "[release-smoke] INFO: MCP autofix mode enabled\n"
fi
check_repo_venv_binaries
check_mcp_configs

printf "\n[release-smoke] Summary: %d passed, %d failed\n" "$PASS_COUNT" "$FAIL_COUNT"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
