#!/usr/bin/env bash
# Copyright (c) Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.

set -euo pipefail

API_BASE_URL="${CODETRUST_API_BASE_URL:-https://api.codetrust.ai}"
TELEMETRY_URL="${API_BASE_URL%/}/v1/telemetry"
PUBLIC_STATS_URL="${API_BASE_URL%/}/v1/stats/public"
WAIT_SECONDS="${TELEMETRY_WAIT_SECONDS:-3}"
MAX_ATTEMPTS="${TELEMETRY_MAX_ATTEMPTS:-10}"

if ! command -v curl >/dev/null 2>&1; then
    printf '[telemetry-smoke] ERROR: curl is required\n' >&2
    exit 1
fi

INSTALLATION_ID="smoke-$(date +%s)-${RANDOM}"
VERSION="smoke-test-1.0.0"

BEFORE_JSON="$(mktemp)"
AFTER_JSON="$(mktemp)"
trap 'rm -f "$BEFORE_JSON" "$AFTER_JSON"' EXIT

printf '[telemetry-smoke] Fetching baseline public stats from %s\n' "$PUBLIC_STATS_URL"
baseline_cache_bust="$(date +%s)-$RANDOM"
curl -fsS "$PUBLIC_STATS_URL?refresh=true&_bust=$baseline_cache_bust" \
    -H 'Cache-Control: no-cache' \
    -H 'Pragma: no-cache' > "$BEFORE_JSON"

printf '[telemetry-smoke] Posting CLI scan_completed event with findings details\n'
curl -fsS -X POST "$TELEMETRY_URL" \
  -H 'Content-Type: application/json' \
  --data-raw "{\"event_type\":\"scan_completed\",\"source\":\"cli\",\"installation_id\":\"${INSTALLATION_ID}\",\"version\":\"${VERSION}\",\"payload\":{\"scan_type\":\"static\",\"files_scanned\":2,\"total_findings\":2,\"findings_by_severity\":{\"BLOCK\":1,\"WARN\":1},\"scan_duration_ms\":123,\"findings\":[{\"rule\":\"hardcoded_secret\",\"rule_id\":\"hardcoded_secret\",\"severity\":\"BLOCK\",\"file\":\"app.py\"},{\"rule\":\"eval_usage\",\"rule_id\":\"eval_usage\",\"severity\":\"WARN\",\"file\":\"worker.py\"}]}}" >/dev/null

printf '[telemetry-smoke] Posting cloud_api scan_completed event with findings details\n'
curl -fsS -X POST "$TELEMETRY_URL" \
  -H 'Content-Type: application/json' \
  --data-raw "{\"event_type\":\"scan_completed\",\"source\":\"cloud_api\",\"installation_id\":\"${INSTALLATION_ID}\",\"version\":\"${VERSION}\",\"payload\":{\"scan_type\":\"deep\",\"files_scanned\":1,\"total_findings\":1,\"findings_by_severity\":{\"BLOCK\":1},\"scan_duration_ms\":77,\"findings\":[{\"rule\":\"command_injection\",\"rule_id\":\"command_injection\",\"severity\":\"BLOCK\",\"file\":\"api.py\"}]}}" >/dev/null

printf '[telemetry-smoke] Waiting %s seconds for async processing\n' "$WAIT_SECONDS"
sleep "$WAIT_SECONDS"

attempt=1
validation_passed=0
while [[ "$attempt" -le "$MAX_ATTEMPTS" ]]; do
    printf '[telemetry-smoke] Fetching updated public stats (attempt %s/%s)\n' "$attempt" "$MAX_ATTEMPTS"
        attempt_cache_bust="$(date +%s)-$RANDOM-$attempt"
        curl -fsS "$PUBLIC_STATS_URL?refresh=true&_bust=$attempt_cache_bust" \
            -H 'Cache-Control: no-cache' \
            -H 'Pragma: no-cache' > "$AFTER_JSON"

    if python3 -c '
import json
import sys

before_path, after_path = sys.argv[1], sys.argv[2]
with open(before_path, "r", encoding="utf-8") as fh:
    before = json.load(fh)
with open(after_path, "r", encoding="utf-8") as fh:
    after = json.load(fh)

stats_before = before.get("stats", {}) if isinstance(before, dict) else {}
stats_after = after.get("stats", {}) if isinstance(after, dict) else {}

usage_before = stats_before.get("usage", {}) if isinstance(stats_before, dict) else {}
usage_after = stats_after.get("usage", {}) if isinstance(stats_after, dict) else {}
impact_after = stats_after.get("impact", {}) if isinstance(stats_after, dict) else {}

errors = []

def get_int(container, key, default=0):
    value = container.get(key, default)
    return int(value) if isinstance(value, (int, float)) else default

total_scan_delta = get_int(usage_after, "total_scans") - get_int(usage_before, "total_scans")
if total_scan_delta < 2:
    errors.append(f"Expected total_scans delta >= 2, got {total_scan_delta}")

scans_by_source_before = usage_before.get("scans_by_source", {})
scans_by_source_after = usage_after.get("scans_by_source", {})
for source in ("cli", "cloud_api"):
    delta = get_int(scans_by_source_after, source) - get_int(scans_by_source_before, source)
    if delta < 1:
        errors.append(f"Expected scans_by_source.{source} delta >= 1, got {delta}")

top_rules = impact_after.get("top_rules", [])
rule_names = {str(item.get("rule", "")) for item in top_rules if isinstance(item, dict)}
expected_rules = {"hardcoded_secret", "eval_usage", "command_injection"}
if not (rule_names & expected_rules):
    errors.append("Expected at least one smoke-test rule in impact.top_rules")

if errors:
    sys.stderr.write("[telemetry-smoke] PENDING\\n")
    for err in errors:
        sys.stderr.write(f" - {err}\\n")
    sys.exit(1)

sys.stdout.write("[telemetry-smoke] PASS\\n")
sys.stdout.write(f" - total_scans delta: {total_scan_delta}\\n")
for source in ("cli", "cloud_api"):
    delta = get_int(scans_by_source_after, source) - get_int(scans_by_source_before, source)
    sys.stdout.write(f" - scans_by_source.{source} delta: {delta}\\n")
sys.stdout.write(f" - top_rules observed: {sorted(rule_names)[:8]}\\n")
    ' "$BEFORE_JSON" "$AFTER_JSON"; then
        validation_passed=1
        break
    fi

    attempt=$((attempt + 1))
    if [[ "$attempt" -le "$MAX_ATTEMPTS" ]]; then
        sleep "$WAIT_SECONDS"
    fi
done

if [[ "$validation_passed" -ne 1 ]]; then
    printf '[telemetry-smoke] FAIL: telemetry deltas did not materialize after %s attempts\n' "$MAX_ATTEMPTS" >&2
    exit 1
fi

printf '[telemetry-smoke] Completed successfully\n'
