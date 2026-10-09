"""Score the Semgrep rules against a regex baseline on the labelled samples.

    python -m brain.evaluate
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

from .decide import THRESHOLD, confidence
from .fetcher import MANIFEST, load_capture
from .scan import scan_capture

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

# What a quick grep-based detector would look for.
BASELINE = re.compile(r"type\s*=\s*[\"']password[\"']|eval\s*\(|atob\s*\(|fetch\s*\(|wget |curl ", re.I)


def baseline_detects(directory: Path) -> bool:
    for path in directory.iterdir():
        if path.name != MANIFEST and BASELINE.search(path.read_text(encoding="utf-8", errors="replace")):
            return True
    return False


def main() -> int:
    rows = []
    for label in ("malicious", "benign"):
        for directory in sorted((SAMPLES / label).iterdir()):
            if not (directory / MANIFEST).exists():
                continue
            findings = scan_capture(load_capture(directory))
            score = confidence(findings)
            rows.append((label, directory.name, score >= THRESHOLD, score, baseline_detects(directory)))

    print(f"{'label':<10} {'sample':<18} {'semgrep':<8} {'score':<6} baseline")
    for label, name, ours, score, base in rows:
        print(f"{label:<10} {name:<18} {'FLAG' if ours else '-':<8} {score:<6} {'FLAG' if base else '-'}")

    def stats(index: int) -> tuple[float, float]:
        tp = sum(1 for r in rows if r[0] == "malicious" and r[index])
        fp = sum(1 for r in rows if r[0] == "benign" and r[index])
        malicious = sum(1 for r in rows if r[0] == "malicious")
        benign = sum(1 for r in rows if r[0] == "benign")
        return (tp / malicious if malicious else 0.0, fp / benign if benign else 0.0)

    print()
    for name, index in (("Semgrep rules", 2), ("Regex baseline", 4)):
        recall, fpr = stats(index)
        print(f"{name:<15} detection rate {recall:.0%}   false-positive rate {fpr:.0%}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
