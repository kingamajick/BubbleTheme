#!/usr/bin/env python3
"""
Sensitive data & secrets scanner.
Scans files in git repository for sensitive strings, API keys, private IPs,
and credentials before commits or pushes.
"""

import os
import re
import subprocess
import sys

# Regex rules for detecting sensitive data
SECRET_PATTERNS = [
    # JWT tokens / HA Long-Lived Access Tokens
    (r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "Home Assistant JWT / Access Token"),
    # Private cryptographic keys
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private cryptographic key"),
    # GitHub personal access tokens
    (r"gh[pousr]_[A-Za-z0-9_]{36,}", "GitHub Token"),
    # Generic API Key / Secret assignments with non-trivial values
    (r"(?i)(api[_-]?key|client[_-]?secret|auth[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]", "API Key / Client Secret"),
    (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"\n\r\t ]{4,}['\"]", "Plaintext Password"),
    # Nabu Casa / Home Assistant Cloud URLs
    (r"[a-z0-9]{16,}\.ui\.nabu\.casa", "Nabu Casa Cloud URL"),
    # Private IPv4 addresses (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
    (r"\b192\.168\.\d{1,3}\.\d{1,3}\b", "Private IP address (192.168.x.x)"),
    (r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "Private IP address (10.x.x.x)"),
    (r"\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b", "Private IP address (172.16-31.x.x)"),
    # GPS coordinates
    (r"(?i)(latitude|longitude)\s*[:=]\s*-?\d{1,3}\.\d{4,}", "GPS Coordinate"),
]

COMPILED_PATTERNS = [(re.compile(p), desc) for p, desc in SECRET_PATTERNS]

EXCLUDED_PATHS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "node_modules",
}

EXCLUDED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot"
}


def get_git_tracked_files(repo_root: str) -> list[str]:
    """Get all git-tracked files in the repository."""
    try:
        output = subprocess.check_output(
            ["git", "-C", repo_root, "ls-files"], text=True
        )
        return [f.strip() for f in output.splitlines() if f.strip()]
    except Exception:
        # Fallback to os.walk
        all_files = []
        for root, dirs, files in os.walk(repo_root):
            dirs[:] = [d for d in dirs if d not in EXCLUDED_PATHS]
            for file in files:
                all_files.append(os.path.relpath(os.path.join(root, file), repo_root))
        return all_files


def scan_file(filepath: str) -> list[tuple[int, str, str]]:
    """Scan a single file for secret patterns. Returns list of (line_num, match, description)."""
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, start=1):
                for pattern, desc in COMPILED_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        matched_text = match.group(0)
                        # Redact the match slightly for terminal display safety
                        redacted = matched_text[:4] + "..." + matched_text[-4:] if len(matched_text) > 8 else "***"
                        findings.append((idx, redacted, desc))
    except Exception as e:
        print(f"Error reading {filepath}: {e}", file=sys.stderr)
    return findings


def main() -> int:
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    files = get_git_tracked_files(repo_root)

    total_violations = 0
    print(f"Scanning {len(files)} files in repository for sensitive data...")

    for rel_path in files:
        _, ext = os.path.splitext(rel_path)
        if ext.lower() in EXCLUDED_EXTENSIONS:
            continue
        if any(part in EXCLUDED_PATHS for part in rel_path.split(os.sep)):
            continue

        abs_path = os.path.join(repo_root, rel_path)
        if not os.path.isfile(abs_path):
            continue

        # Don't scan the scanner itself for patterns!
        if os.path.basename(rel_path) == "check_secrets.py":
            continue

        findings = scan_file(abs_path)
        if findings:
            total_violations += len(findings)
            print(f"\n[FAIL] SENSITIVE DATA DETECTED in {rel_path}:")
            for line_no, sample, desc in findings:
                print(f"  Line {line_no}: Found {desc} ({sample})")

    if total_violations > 0:
        print(f"\nScan aborted: {total_violations} sensitive data violation(s) detected.")
        print("Please remove secrets / private IP addresses before committing or pushing.")
        return 1

    print("[PASS] No secrets or sensitive data detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
