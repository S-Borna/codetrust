# CodeTrust Load Test Baselines

## Performance Targets

Based on initial load testing with [Locust](https://locust.io/), these are the established performance baselines for CodeTrust API endpoints.

### Endpoint Baselines

| Endpoint | Method | p50 | p95 | p99 | Target RPS | Status |
|----------|--------|-----|-----|-----|------------|--------|
| `/v1/status` | GET | < 5ms | < 20ms | < 50ms | 500+ | ✅ Baseline |
| `/v1/scan/static` | POST | < 50ms | < 200ms | < 500ms | 100+ | ✅ Baseline |
| `/v1/scan/deep` | POST | < 200ms | < 800ms | < 2000ms | 50+ | ✅ Baseline |
| `/v1/scan/ast` | POST | < 100ms | < 400ms | < 1000ms | 80+ | ✅ Baseline |
| `/metrics` | GET | < 5ms | < 15ms | < 30ms | 500+ | ✅ Baseline |
| `/v1/governance/audit` | GET | < 30ms | < 100ms | < 250ms | 200+ | ✅ Baseline |

### System-Level Baselines

| Metric | Target | Threshold |
|--------|--------|-----------|
| CPU utilization (steady-state) | < 50% | Alert at 80% |
| Memory usage (per worker) | < 256MB | Alert at 512MB |
| Error rate | < 0.1% | Alert at 1% |
| Connection pool utilization | < 70% | Alert at 90% |
| Database query p95 | < 50ms | Alert at 200ms |
| Redis cache hit rate | > 80% | Alert at 60% |
| Request queue depth | < 10 | Alert at 50 |

### Scalability Matrix

| Concurrent Users | Expected RPS | p95 Latency | Notes |
|------------------|--------------|-------------|-------|
| 10 | 200+ | < 100ms | Single instance |
| 50 | 500+ | < 200ms | Single instance |
| 100 | 800+ | < 400ms | 2 workers |
| 500 | 2000+ | < 500ms | 4 workers + HPA |
| 1000 | 3000+ | < 800ms | Auto-scaled cluster |

## Running Load Tests

### Prerequisites

```bash
pip install locust
```

### Quick Run

```bash
# Against local server
locust -f tests/load/locustfile.py --host http://localhost:8000 \
  --users 50 --spawn-rate 5 --run-time 2m --headless

# Against staging
locust -f tests/load/locustfile.py --host https://api.codetrust.ai \
  --users 100 --spawn-rate 10 --run-time 5m --headless
```

### Full Benchmark Suite

```bash
# Ramp-up test (10 → 200 users over 5 minutes)
locust -f tests/load/locustfile.py --host http://localhost:8000 \
  --users 200 --spawn-rate 2 --run-time 5m --headless \
  --csv=load_results

# Soak test (steady 50 users for 30 minutes)
locust -f tests/load/locustfile.py --host http://localhost:8000 \
  --users 50 --spawn-rate 50 --run-time 30m --headless \
  --csv=soak_results
```

### Interpreting Results

After each run, Locust generates CSV files:

- `*_stats.csv` — Per-endpoint stats (p50, p95, p99, RPS, failures)
- `*_stats_history.csv` — Time-series data for trending
- `*_failures.csv` — Error details
- `*_exceptions.csv` — Exception traces

### CI Integration

```yaml
# .github/workflows/ci.yml (optional load test stage)
  load-test:
    runs-on: ubuntu-latest
    needs: lint-and-test
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install locust
      - run: |
          locust -f tests/load/locustfile.py \
            --host http://localhost:8000 \
            --users 50 --spawn-rate 10 \
            --run-time 1m --headless \
            --csv=load_results \
            --exit-code-on-error 1
      - uses: actions/upload-artifact@v4
        with:
          name: load-test-results
          path: load_results*.csv
```

## Alerting Thresholds

When p95 latency exceeds 2x the baseline for 5+ minutes, trigger:

1. **Warning**: Slack notification to `#ops-alerts`
2. **Critical**: PagerDuty if p95 > 5x baseline for 10+ minutes
3. **Auto-scale**: HPA triggers at 70% CPU or 50+ request queue depth

## Revision History

| Date | Change | Author |
|------|--------|--------|
| 2025-01-01 | Initial baselines established | CodeTrust Team |
