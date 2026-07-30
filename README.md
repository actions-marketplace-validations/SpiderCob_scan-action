# SpiderCob Security Scan — Offline GitHub Action

> **Zero setup** — no account, no API token, fully offline. Runs regex scanning locally on the GitHub runner.
> For higher accuracy with ML-powered detection, try [SpiderCob/dlp-scan-action](https://github.com/marketplace/actions/dlp-secret-scan).

Scan your code for hardcoded secrets, PII, and vulnerabilities — no signup required, no data leaves the runner.

- **Fully offline** — no network calls, no account needed
- Detects 40+ secret patterns: AWS, GitHub, OpenAI, Anthropic, Stripe, Slack, Google, and more
- Detects PII: SSN, credit cards, email addresses, phone numbers
- Detects vulnerable code: SQL injection, command injection, XSS, path traversal, and more
- Inline GitHub annotations on the PR diff
- Configurable fail threshold and changed-files-only mode

## Quick start

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  spidercob:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: SpiderCob/scan-action@v1
```

No token required. Works immediately.

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

**Scan only changed files, fail on CRITICAL only:**
```yaml
- uses: SpiderCob/scan-action@v1
  with:
    changed_files_only: 'true'
    fail_on: CRITICAL
```

**DLP only (PII detection):**
```yaml
- uses: SpiderCob/scan-action@v1
  with:
    scan_type: dlp
```

## Which action should I use?

| | `scan-action` (this) | `dlp-scan-action` |
|---|---|---|
| **Detection** | Regex only | ML-powered, high accuracy |
| **False positives** | Higher | Minimal (ML filters test data) |
| **Account needed** | No | Yes (free) |
| **Internet required** | No | Yes |
| **Recommendation** | Air-gapped / privacy-first / quick start | Most users |

## Learn more

- [SpiderCob on PyPI](https://pypi.org/project/spidercob/)
- [SpiderCob Enterprise](https://spidercob.com) — full DLP platform with dashboard, ICAP proxy, audit trail

