# CodeTrust CI/CD Integrations

CodeTrust integrates with all major CI/CD platforms to scan your code for anti-patterns, security issues, and hallucinated packages on every commit and pull request.

## Supported Platforms

| Platform | Template File | Status |
|----------|--------------|--------|
| GitHub Actions | `action.yml` | Production |
| Jenkins | `Jenkinsfile` | Production |
| GitLab CI | `gitlab-ci.yml` | Production |
| Azure Pipelines | `azure-pipelines.yml` | Production |
| Bitbucket Pipelines | `bitbucket-pipelines.yml` | Production |

## Configuration Options

All integrations support the same core options:

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `CODETRUST_API_KEY` | string | (required) | Your CodeTrust API key |
| `CODETRUST_API_URL` | URL | `https://api.codetrust.ai` | API endpoint |
| `CODETRUST_FAIL_ON` | `block`, `warn`, `never` | `block` | Severity threshold that fails the build |
| `CODETRUST_SCAN_TYPE` | `static`, `deep` | `static` | Scan depth |
| `CODETRUST_LANGUAGE` | `python`, `javascript`, `typescript`, `go`, `rust` | auto | Force language detection |
| `CODETRUST_SCAN_PATH` | path | `.` | File or directory to scan |

## Pull Request Scanning

All integrations automatically detect pull request / merge request contexts and scan only changed files, reducing scan time and noise. In PR mode, only new findings (not present in the base branch) trigger failures.

---

## GitHub Actions

The GitHub Action is the primary integration. See `action.yml` for the full spec.

### Setup

1. Add your API key to repository secrets:
   **Settings > Secrets and variables > Actions > New repository secret**
   Name: `CODETRUST_API_KEY`

2. Create `.github/workflows/codetrust.yml`:

```yaml
name: CodeTrust
on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: s-borna/codetrust@main
        with:
          api-key: ${{ secrets.CODETRUST_API_KEY }}
          fail-on: block
          scan-type: static
          sarif: true

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: codetrust-results.sarif
```

---

## Jenkins

### Setup

1. Store your API key in Jenkins Credentials:
   **Manage Jenkins > Credentials > System > Global credentials > Add Credentials**
   - Kind: Secret text
   - Secret: (your API key)
   - ID: `codetrust-api-key`

2. Use the provided `Jenkinsfile` directly, or add a stage to your existing pipeline:

```groovy
pipeline {
    agent any
    environment {
        CODETRUST_API_KEY = credentials('codetrust-api-key')
    }
    stages {
        stage('CodeTrust Scan') {
            steps {
                sh 'pip install --quiet codetrust'
                sh 'codetrust scan --format json --fail-on block . > codetrust-results.json'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'codetrust-results.json', allowEmptyArchive: true
        }
    }
}
```

### Parameters

The full `Jenkinsfile` supports build parameters:

- **FAIL_ON**: `block` (default), `warn`, or `never`
- **SCAN_TYPE**: `static` (default) or `deep`
- **SCAN_PATH**: directory or file to scan (default: `.`)
- **LANGUAGE**: force language detection (default: auto)

### Pipeline as Shared Library

For multi-repo setups, add the Jenkinsfile to a shared library and reference it:

```groovy
@Library('codetrust-pipeline') _
codetrust(failOn: 'block', scanType: 'static')
```

---

## GitLab CI

### Setup

1. Store your API key as a CI/CD variable:
   **Settings > CI/CD > Variables > Add variable**
   - Key: `CODETRUST_API_KEY`
   - Value: (your API key)
   - Flags: Mask variable, Protect variable

2. Include the template in your `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/s-borna/codetrust/main/action/gitlab-ci.yml'

stages:
  - test

# The 'codetrust' job is defined in the template and runs in the 'test' stage
```

Or for local inclusion (copy `gitlab-ci.yml` to your repo):

```yaml
include:
  - local: 'ci/codetrust.yml'
```

### Customization

Override variables per-job:

```yaml
codetrust:
  extends: .codetrust-scan
  stage: test
  variables:
    CODETRUST_FAIL_ON: "warn"
    CODETRUST_SCAN_TYPE: "deep"
    CODETRUST_LANGUAGE: "python"
```

### SARIF Integration

The GitLab template automatically uploads SARIF results as a `sast` report artifact. This integrates with GitLab's Security Dashboard if you have GitLab Ultimate.

### Merge Request Pipelines

The template automatically detects merge request pipelines and scans only changed files using `CI_MERGE_REQUEST_DIFF_BASE_SHA`.

---

## Azure Pipelines

### Setup

1. Store your API key in a variable group or pipeline variable:
   **Pipelines > Library > Variable groups > New variable group**
   - Name: `codetrust-vars`
   - Add variable: `CODETRUST_API_KEY` (mark as secret)
   - Optionally: `CODETRUST_API_URL`

   Or in pipeline settings:
   **Pipelines > (your pipeline) > Edit > Variables**

2. Reference the template in your `azure-pipelines.yml`:

```yaml
resources:
  repositories:
    - repository: codetrust
      type: github
      endpoint: github-service-connection
      name: s-borna/codetrust
      ref: main

variables:
  - group: codetrust-vars

stages:
  - stage: Security
    jobs:
      - template: action/azure-pipelines.yml@codetrust
        parameters:
          failOn: 'block'
          scanType: 'static'
```

Or copy the template and use inline:

```yaml
variables:
  - group: codetrust-vars

jobs:
  - template: action/azure-pipelines.yml
    parameters:
      failOn: 'block'
```

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `failOn` | `block` | Failure threshold |
| `scanType` | `static` | Scan depth |
| `scanPath` | `.` | Path to scan |
| `language` | (auto) | Force language |
| `pythonVersion` | `3.12` | Python version |

### Azure DevOps Code Scanning

SARIF results are published as build artifacts under `CodeAnalysisLogs`. If you have Azure DevOps Advanced Security enabled, these integrate with the Code Scanning alerts view.

### Pull Request Builds

The template detects pull request builds via `SYSTEM_PULLREQUEST_TARGETBRANCH` and scans only changed files.

---

## Bitbucket Pipelines

### Setup

1. Store your API key as a repository variable:
   **Repository settings > Pipelines > Repository variables**
   - Name: `CODETRUST_API_KEY`
   - Value: (your API key)
   - Secured: Yes

2. Add to your `bitbucket-pipelines.yml`:

```yaml
definitions:
  steps:
    - step: &codetrust-scan
        name: 'CodeTrust Security Scan'
        image: python:3.12-slim
        caches:
          - pip
        script:
          - pip install --quiet codetrust
          - codetrust scan --format json --fail-on block . > codetrust-results.json
          - codetrust scan --format sarif --output codetrust-results.sarif . || true
          - |
            python3 -c "
            import json
            data = json.load(open('codetrust-results.json'))
            print(f'Verdict: {data.get(\"verdict\", \"UNKNOWN\")}')
            print(f'Findings: {data.get(\"total_findings\", 0)}')
            "
        artifacts:
          - codetrust-results.json
          - codetrust-results.sarif

pipelines:
  pull-requests:
    '**':
      - step: *codetrust-scan
  branches:
    main:
      - step: *codetrust-scan
```

Or use the full template from `bitbucket-pipelines.yml` which includes PR file detection and configurable thresholds.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CODETRUST_API_KEY` | (required) | API key (secured variable) |
| `CODETRUST_API_URL` | `https://api.codetrust.ai` | API endpoint |
| `CODETRUST_FAIL_ON` | `block` | Failure threshold |
| `CODETRUST_SCAN_TYPE` | `static` | Scan depth |
| `CODETRUST_LANGUAGE` | (auto) | Force language |

### Pull Request Scanning

The template detects pull request pipelines via `BITBUCKET_PR_DESTINATION_BRANCH` and scans only changed files.

---

## Example Output

All integrations produce similar console output:

```
==================================================
CodeTrust Verdict: BLOCK
Total findings: 3
  BLOCK: 1  WARN: 2
==================================================
[BLOCK] src/api.py:42 -- eval_exec: eval/exec is a security risk.
[WARN]  src/utils.py:15 -- bare_except: Bare except. Catch specific exceptions.
[WARN]  src/config.py:8 -- hardcoded_secret: Possible hardcoded secret. Use environment variables.
```

### SARIF Output

All integrations generate SARIF v2.1.0 output (`codetrust-results.sarif`) compatible with:
- GitHub Code Scanning (Advanced Security)
- GitLab Security Dashboard (Ultimate)
- Azure DevOps Code Scanning (Advanced Security)
- Any SARIF-compatible viewer

---

## Troubleshooting

### Common Issues

**Build fails with "codetrust: command not found"**
Ensure Python 3.12+ is available and `pip install codetrust` completes successfully. Check that the pip bin directory is on PATH.

**API key not found**
Verify the API key variable name matches your CI platform's convention:
- GitHub: `${{ secrets.CODETRUST_API_KEY }}`
- Jenkins: `credentials('codetrust-api-key')`
- GitLab: `$CODETRUST_API_KEY` (CI/CD variable)
- Azure: `$(CODETRUST_API_KEY)` (variable group or pipeline variable)
- Bitbucket: `$CODETRUST_API_KEY` (repository variable)

**No changed files detected in PR mode**
Ensure full git history is available. Most CI systems perform shallow clones by default:
- GitHub: use `fetch-depth: 0` in `actions/checkout`
- GitLab: set `GIT_DEPTH: 0` or use default
- Azure: set `fetchDepth: 0` in checkout step
- Bitbucket: set `clone: depth: full` in pipeline options

**Scan times out**
For large repositories, consider:
- Using `CODETRUST_SCAN_PATH` to limit scope
- Setting `CODETRUST_LANGUAGE` to avoid auto-detection overhead
- Using `static` scan type instead of `deep`

**SARIF upload fails**
Verify the SARIF file path matches between the scan step and the upload step. The default path is `codetrust-results.sarif` in the workspace root.

### Getting Help

- Documentation: https://docs.codetrust.ai
- Issues: https://github.com/s-borna/codetrust/issues
- Email: support@codetrust.ai
