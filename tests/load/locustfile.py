"""Locust load testing for CodeTrust API.

Usage:
    # Install: pip install locust
    # Run:     locust -f tests/load/locustfile.py --host http://localhost:8000
    # Web UI:  http://localhost:8089

    # Headless (CI):
    locust -f tests/load/locustfile.py \
        --host http://localhost:8000 \
        --headless -u 50 -r 10 --run-time 60s \
        --csv results/load

Scenarios:
    1. HealthCheck — GET /v1/status (lightweight, baseline)
    2. StaticScan — POST /v1/scan/static (core feature)
    3. DeepScan — POST /v1/scan/deep (heavy, full pipeline)
    4. ScanHistory — GET /v1/scans/history (read path)
    5. Metrics — GET /metrics (monitoring endpoint)
"""

from __future__ import annotations

from locust import HttpUser, between, tag, task

# --- Sample code snippets for scan payloads ---

PYTHON_SAFE = '''\
import os
import sys

def main():
    """Entry point."""
    name = os.getenv("USER", "world")
    print(f"Hello, {name}!")
    return 0

if __name__ == "__main__":
    sys.exit(main())
'''

PYTHON_RISKY = '''\
import os
import subprocess

API_KEY = "sk-1234567890abcdef"

def run_cmd(cmd):
    return eval(cmd)

def deploy():
    subprocess.call(f"rm -rf /tmp/{os.getenv('DIR')}", shell=True)
    magic = 3.14159
    return magic
'''

JS_CODE = '''\
const axios = require("axios");
const API_KEY = "ghp_ABC123secrettoken456";

async function fetchData() {
    const resp = await axios.get("https://api.example.com/data");
    return resp.data;
}

module.exports = { fetchData };
'''

DOCKERFILE = '''\
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "main.py"]
'''


class CodeTrustUser(HttpUser):
    """Simulates a typical CodeTrust API consumer."""

    wait_time = between(0.5, 2.0)

    def on_start(self) -> None:
        """Set up headers for authenticated requests."""
        self.headers = {"Content-Type": "application/json"}
        # Add API key if available
        api_key = self.environment.parsed_options
        if hasattr(api_key, "api_key") and api_key.api_key:
            self.headers["X-API-Key"] = api_key.api_key

    # --- Health & monitoring ---

    @tag("health")
    @task(5)
    def health_check(self) -> None:
        """GET /v1/status — lightweight health probe."""
        self.client.get("/v1/status", name="/v1/status")

    @tag("metrics")
    @task(2)
    def metrics(self) -> None:
        """GET /metrics — Prometheus metrics endpoint."""
        self.client.get("/metrics", name="/metrics")

    # --- Static scans (core feature) ---

    @tag("scan", "static")
    @task(10)
    def static_scan_python_safe(self) -> None:
        """POST /v1/scan/static — safe Python code."""
        self.client.post(
            "/v1/scan/static",
            json={"code": PYTHON_SAFE, "filename": "main.py"},
            headers=self.headers,
            name="/v1/scan/static [safe]",
        )

    @tag("scan", "static")
    @task(8)
    def static_scan_python_risky(self) -> None:
        """POST /v1/scan/static — risky Python code with findings."""
        self.client.post(
            "/v1/scan/static",
            json={"code": PYTHON_RISKY, "filename": "deploy.py"},
            headers=self.headers,
            name="/v1/scan/static [risky]",
        )

    @tag("scan", "static")
    @task(5)
    def static_scan_javascript(self) -> None:
        """POST /v1/scan/static — JavaScript code."""
        self.client.post(
            "/v1/scan/static",
            json={"code": JS_CODE, "filename": "app.js"},
            headers=self.headers,
            name="/v1/scan/static [js]",
        )

    # --- SARIF output ---

    @tag("scan", "sarif")
    @task(3)
    def static_scan_sarif(self) -> None:
        """POST /v1/scan/static/sarif — SARIF format output."""
        self.client.post(
            "/v1/scan/static/sarif",
            json={"code": PYTHON_RISKY, "filename": "deploy.py"},
            headers=self.headers,
            name="/v1/scan/static/sarif",
        )

    # --- Deep scans (heavy) ---

    @tag("scan", "deep")
    @task(2)
    def deep_scan(self) -> None:
        """POST /v1/scan/deep — full multi-layer scan."""
        self.client.post(
            "/v1/scan/deep",
            json={
                "code": PYTHON_RISKY,
                "filename": "deploy.py",
                "language": "python",
                "verify_imports": False,
                "verify_docker": False,
                "sandbox_run": False,
            },
            headers=self.headers,
            name="/v1/scan/deep",
        )

    @tag("scan", "deep")
    @task(1)
    def deep_scan_with_docker(self) -> None:
        """POST /v1/scan/deep — with Dockerfile verification."""
        self.client.post(
            "/v1/scan/deep",
            json={
                "code": PYTHON_SAFE,
                "filename": "main.py",
                "language": "python",
                "verify_imports": False,
                "verify_docker": True,
                "dockerfile_content": DOCKERFILE,
                "sandbox_run": False,
            },
            headers=self.headers,
            name="/v1/scan/deep [docker]",
        )

    # --- Governance audit ---

    @tag("governance")
    @task(2)
    def governance_audit(self) -> None:
        """GET /v1/governance/audit — query audit log."""
        self.client.get(
            "/v1/governance/audit?hours=24&limit=50",
            headers=self.headers,
            name="/v1/governance/audit",
        )


class HeavyUser(HttpUser):
    """Simulates a power user running many deep scans."""

    wait_time = between(0.2, 1.0)
    weight = 1  # Lower weight — fewer heavy users

    @tag("scan", "deep", "heavy")
    @task
    def deep_scan_burst(self) -> None:
        """POST /v1/scan/deep — burst of deep scans."""
        self.client.post(
            "/v1/scan/deep",
            json={
                "code": PYTHON_RISKY,
                "filename": "app.py",
                "language": "python",
                "verify_imports": True,
                "verify_docker": False,
                "sandbox_run": False,
            },
            headers={"Content-Type": "application/json"},
            name="/v1/scan/deep [burst]",
        )
