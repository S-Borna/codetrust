#!/usr/bin/env bash
# CodeTrust GitHub Action entrypoint
# Scans code and outputs results in SARIF format
set -euo pipefail

# ---- Configuration ----
SCAN_TYPE="${CODETRUST_SCAN_TYPE:-deep}"
FAIL_ON="${CODETRUST_FAIL_ON:-block}"
LANGUAGE="${CODETRUST_LANGUAGE:-python}"
SCAN_PATH="${CODETRUST_SCAN_PATH:-.}"
SARIF_FILE="${CODETRUST_SARIF_FILE:-codetrust-results.sarif}"
MAX_FILE_SIZE="${CODETRUST_MAX_FILE_SIZE:-500000}"
INCLUDE_PATTERN="${CODETRUST_INCLUDE_PATTERN:-}"
CT_AUTH="${CODETRUST_API_KEY:-}"
API_URL="${CODETRUST_API_URL:-https://api.codetrust.ai}"
PR_MODE="${CODETRUST_PR_MODE:-auto}"
PR_COMMENT="${CODETRUST_PR_COMMENT:-auto}"
NEW_FINDINGS_ONLY="${CODETRUST_NEW_FINDINGS_ONLY:-auto}"

# ---- Resolve action root ----
ACTION_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---- Run scan ----
echo "::group::CodeTrust Scan"
echo "Scan type: ${SCAN_TYPE}"
echo "Language:  ${LANGUAGE}"
echo "Path:      ${SCAN_PATH}"
echo "Fail on:   ${FAIL_ON}"

python3 "${ACTION_ROOT}/action/scan_runner.py" \
  --scan-type "${SCAN_TYPE}" \
  --language "${LANGUAGE}" \
  --path "${SCAN_PATH}" \
  --sarif-file "${SARIF_FILE}" \
  --fail-on "${FAIL_ON}" \
  --max-file-size "${MAX_FILE_SIZE}" \
  --include-pattern "${INCLUDE_PATTERN}" \
  --pr-mode "${PR_MODE}" \
  --pr-comment "${PR_COMMENT}" \
  --new-findings-only "${NEW_FINDINGS_ONLY}" \
  --api-key "${CT_AUTH}" \
  --api-url "${API_URL}"

EXIT_CODE=$?
echo "::endgroup::"

exit ${EXIT_CODE}
