#!/usr/bin/env python3
"""
SpiderCob GitHub Action scanner.
Scans source files for secrets, PII, and vulnerabilities.
Outputs GitHub Actions annotations and sets step outputs.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# ── Config from env ───────────────────────────────────────────────────────────

SCAN_PATH    = os.environ.get("SPIDERCOB_SCAN_PATH", ".")
FAIL_ON      = os.environ.get("SPIDERCOB_FAIL_ON", "HIGH").upper()
SCAN_TYPE    = os.environ.get("SPIDERCOB_SCAN_TYPE", "both").lower()
EXCLUDE      = [p.strip() for p in os.environ.get("SPIDERCOB_EXCLUDE", "").split(",") if p.strip()]
CHANGED_ONLY = os.environ.get("SPIDERCOB_CHANGED_ONLY", "false").lower() == "true"
GITHUB_OUTPUT = os.environ.get("GITHUB_OUTPUT", "")
GITHUB_STEP_SUMMARY = os.environ.get("GITHUB_STEP_SUMMARY", "")

SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# File extensions to scan
CODE_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php",
    ".cs", ".cpp", ".c", ".h", ".rs", ".swift", ".kt", ".scala",
    ".sh", ".bash", ".zsh", ".yaml", ".yml", ".json", ".toml", ".env",
    ".tf", ".hcl", ".sql", ".dockerfile", ".conf", ".cfg", ".ini",
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def get_changed_files() -> list[Path]:
    """Get files changed in the current PR/push via git diff."""
    try:
        base = os.environ.get("GITHUB_BASE_REF", "HEAD~1")
        result = subprocess.run(
            ["git", "diff", "--name-only", f"origin/{base}...HEAD"],
            capture_output=True, text=True, check=True
        )
        return [Path(f) for f in result.stdout.splitlines() if f.strip()]
    except Exception:
        return []

def collect_files(root: Path) -> list[Path]:
    if CHANGED_ONLY:
        files = get_changed_files()
        return [root / f for f in files if (root / f).is_file()]
    return [
        p for p in root.rglob("*")
        if p.is_file()
        and p.suffix.lower() in CODE_EXTS
        and not any(part.startswith(".") or part in ("node_modules", "__pycache__", ".venv", "venv", "dist", "build") for part in p.parts)
    ]

def gh_annotation(level: str, filepath: str, line: int, message: str):
    """Print a GitHub Actions annotation."""
    sev_to_level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "notice"}
    ann = sev_to_level.get(level, "notice")
    print(f"::{ann} file={filepath},line={line}::{message}")

def set_output(name: str, value: str):
    if GITHUB_OUTPUT:
        with open(GITHUB_OUTPUT, "a") as f:
            f.write(f"{name}={value}\n")
    else:
        print(f"::set-output name={name}::{value}")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    from spidercob import DLPScanner, CodeScanner

    code_scanner = CodeScanner() if SCAN_TYPE in ("code", "both") else None
    dlp_scanner  = DLPScanner()  if SCAN_TYPE in ("dlp",  "both") else None

    root = Path(SCAN_PATH).resolve()
    files = collect_files(root)

    print(f"\n SpiderCob Security Scan")
    print(f"   Scanning {len(files)} files in {root}")
    print(f"   Mode: {SCAN_TYPE} | Fail on: {FAIL_ON} | Changed only: {CHANGED_ONLY}\n")

    all_findings: list[dict] = []
    all_compliance: set[str] = set()
    files_with_findings = 0

    for filepath in files:
        rel = str(filepath.relative_to(Path.cwd()))
        try:
            text = filepath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        file_findings = []

        if code_scanner:
            result = code_scanner.scan(text, filename=rel)
            for f in result["findings"]:
                f["_file"] = rel
                file_findings.append(f)
            all_compliance.update(result.get("compliance_alerts", []))

        if dlp_scanner:
            result = dlp_scanner.scan(text)
            for f in result["findings"]:
                # DLP findings don't have line numbers — approximate from start offset
                line = text[:f.get("start", 0)].count("\n") + 1
                f["line"] = line
                f["_file"] = rel
                file_findings.append(f)
            all_compliance.update(result.get("compliance_alerts", []))

        if file_findings:
            files_with_findings += 1
            for f in file_findings:
                sev = f.get("severity", "LOW")
                name = f.get("type", "unknown")
                line = f.get("line", 1)
                val  = f.get("value", "")
                gh_annotation(sev, rel, line, f"[SpiderCob] {name} ({sev}): {val}")

        all_findings.extend(file_findings)

    # ── Summary ───────────────────────────────────────────────────────────────

    total = len(all_findings)
    highest = "NONE"
    for f in all_findings:
        sev = f.get("severity", "NONE")
        if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(highest, 0):
            highest = sev

    verdict = "ALLOW"
    if total > 0:
        verdict = "BLOCK" if SEVERITY_RANK.get(highest, 0) >= SEVERITY_RANK.get(FAIL_ON, 3) else "REVIEW"

    compliance_list = sorted(all_compliance)
    compliance_str  = ", ".join(compliance_list) if compliance_list else "None"

    print(f"\n Scan complete")
    print(f"   Files scanned  : {len(files)}")
    print(f"   Files flagged  : {files_with_findings}")
    print(f"   Total findings : {total}")
    print(f"   Highest risk   : {highest}")
    print(f"   Verdict        : {verdict}")
    if compliance_list:
        print(f"   Compliance     : {compliance_str}")
    print()

    # Write GitHub Step Summary if available
    if GITHUB_STEP_SUMMARY:
        with open(GITHUB_STEP_SUMMARY, "a") as f:
            f.write("## SpiderCob Security Scan\n\n")
            f.write(f"| | |\n|---|---|\n")
            f.write(f"| **Files scanned** | {len(files)} |\n")
            f.write(f"| **Findings** | {total} |\n")
            f.write(f"| **Highest risk** | {highest} |\n")
            f.write(f"| **Verdict** | {verdict} |\n")
            if compliance_list:
                f.write(f"| **Compliance alerts** | {compliance_str} |\n")
            f.write("\n")

    set_output("findings_count", str(total))
    set_output("risk_level", highest)
    set_output("verdict", verdict)
    set_output("compliance_alerts", compliance_str)

    if verdict == "BLOCK":
        print(f"::error::SpiderCob blocked: {total} finding(s) at {highest} severity. Review annotations above.")
        sys.exit(1)

    if verdict == "REVIEW":
        print(f"::warning::SpiderCob found {total} finding(s) for review (below fail threshold '{FAIL_ON}').")

if __name__ == "__main__":
    main()
