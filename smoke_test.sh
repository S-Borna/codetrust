#!/usr/bin/env bash
# ============================================================
#  CodeTrust — Production Smoke Test
#  Usage: ./smoke_test.sh https://your-app.up.railway.app
# ============================================================
set -euo pipefail

BASE_URL="${1:?Usage: $0 <base-url>}"
PASS=0
FAIL=0

green() { printf "\033[32m✅ %s\033[0m\n" "$1"; }
red()   { printf "\033[31m❌ %s\033[0m\n" "$1"; }

check() {
    local name="$1" url="$2" method="${3:-GET}" body="${4:-}"
    local args=(-s -o /tmp/ct_smoke.json -w "%{http_code}" -X "$method")
    if [ -n "$body" ]; then
        args+=(-H "Content-Type: application/json" -d "$body")
    fi
    local status
    status=$(curl "${args[@]}" "$url")
    if [ "$status" -ge 200 ] && [ "$status" -lt 300 ]; then
        green "$name (HTTP $status)"
        PASS=$((PASS + 1))
    else
        red "$name (HTTP $status)"
        cat /tmp/ct_smoke.json 2>/dev/null | head -3
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo "============================================"
echo "  CodeTrust Smoke Test"
echo "  Target: $BASE_URL"
echo "============================================"
echo ""

# 1. Health check
check "Health" "$BASE_URL/v1/status"

# 2. Static scan — clean code
check "Static scan (clean)" "$BASE_URL/v1/scan/static" POST \
    '{"code":"def hello():\n    return 42\n","filename":"test.py"}'

# 3. Static scan — code with findings
check "Static scan (findings)" "$BASE_URL/v1/scan/static" POST \
    '{"code":"import os\nprint(os.getenv(\"SECRET\"))\n","filename":"bad.py"}'

# 4. AST scan
check "AST scan" "$BASE_URL/v1/scan/ast" POST \
    '{"code":"def f():\n    if True:\n        if True:\n            if True:\n                pass\n","filename":"deep.py","language":"python"}'

# 5. Deep scan
check "Deep scan" "$BASE_URL/v1/scan/deep" POST \
    '{"code":"import requests\nresponse = requests.get(\"https://api.example.com\")\n","filename":"app.py"}'

# 6. SARIF export
check "SARIF export" "$BASE_URL/v1/scan/static/sarif" POST \
    '{"code":"x = 42\nprint(x)\n","filename":"example.py"}'

# 7. Import verification
check "Import verify" "$BASE_URL/v1/verify/imports" POST \
    '{"imports":["requests","flask","numpy"],"language":"python"}'

# 8. Empty file (regression test for 422 bug)
check "Empty file" "$BASE_URL/v1/scan/static" POST \
    '{"code":"","filename":"__init__.py"}'

# 9. Auth config check (should return 4xx/503 if not configured, not 500)
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/v1/auth/github" \
    -H "Content-Type: application/json" -d '{"code":"fake_code"}')
if [ "$status" != "500" ]; then
    green "Auth endpoint (no 500, got $status)"
    PASS=$((PASS + 1))
else
    red "Auth endpoint (HTTP $status — server error!)"
    FAIL=$((FAIL + 1))
fi

# 10. Profile without token (should return 401/403, not 500)
status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/v1/profile")
if [ "$status" -lt 500 ]; then
    green "Profile unauthorized (no 500, got $status)"
    PASS=$((PASS + 1))
else
    red "Profile endpoint (HTTP $status — server error!)"
    FAIL=$((FAIL + 1))
fi

# 11. Vulnerability scan
check "Vuln scan" "$BASE_URL/v1/vuln/scan" POST \
    '{"language":"python","packages":["requests"]}'

# 12. License scan
check "License scan" "$BASE_URL/v1/license/scan" POST \
    '{"language":"python","packages":["requests"]}'

# 13. Cross-file analysis
check "Cross-file scan" "$BASE_URL/v1/scan/cross-file" POST \
    '{"files":{"main.py":"from utils import helper\n","utils.py":"def helper(): pass\n"}}'

# 14. Auto-fix
check "Auto-fix" "$BASE_URL/v1/fix/apply" POST \
    '{"files":{"app.py":"print(\"hello\")\n"},"languages":{"app.py":"python"}}'

echo ""
echo "============================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "============================================"
echo ""

rm -f /tmp/ct_smoke.json

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
