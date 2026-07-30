# SpiderCob Security Scan — GitHub Action

Scan your code for hardcoded secrets, PII, and vulnerabilities on every push and pull request. Powered by [spidercob](https://pypi.org/project/spidercob/).

- Detects 40+ secret patterns (AWS, GitHub, OpenAI, Stripe, Slack, and more)
- Detects PII (SSN, credit cards, emails, phone numbers)
- Detects vulnerable code patterns (SQL injection, command injection, XSS, and more)
- Inline GitHub annotations — findings appear directly on the diff
- Fully offline — no data sent anywhere
- Zero configuration required

## Quick Start

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  spidercob:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: spidercob/scan-action@v1
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `scan_type` | `both` | `code` (secrets + vulns), `dlp` (PII), or `both` |
| `fail_on` | `HIGH` | Minimum severity to fail: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE` |
| `scan_path` | `.` | Directory to scan |
| `changed_files_only` | `false` | Only scan files changed in this PR |
| `exclude_patterns` | `` | Comma-separated pattern IDs to skip |

## Outputs

| Output | Description |
|---|---|
| `findings_count` | Total number of findings |
| `risk_level` | Highest severity found |
| `verdict` | `BLOCK`, `REVIEW`, or `ALLOW` |

## Examples

**Scan only changed files in PRs, fail on CRITICAL only:**

```yaml
- uses: spidercob/scan-action@v1
  with:
    changed_files_only: 'true'
    fail_on: CRITICAL
```

**DLP-only scan (PII detection):**

```yaml
- uses: spidercob/scan-action@v1
  with:
    scan_type: dlp
    fail_on: HIGH
```

**Use outputs in subsequent steps:**

```yaml
- uses: spidercob/scan-action@v1
  id: spidercob
- run: echo "Found ${{ steps.spidercob.outputs.findings_count }} issues"
```

## Learn More

- [spidercob on PyPI](https://pypi.org/project/spidercob/)
- [SpiderCob Enterprise](https://spidercob.com) — full DLP platform with dashboard, ICAP proxy, and ML classification
