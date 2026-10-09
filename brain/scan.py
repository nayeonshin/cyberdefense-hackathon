"""Run the Semgrep rules over a capture directory."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlparse

from .fetcher import MANIFEST, Capture

RULES_DIR = Path(__file__).resolve().parent.parent / "semgrep-rules"
SCAN_TIMEOUT_S = 120
URL_RE = re.compile(r"https?://[^\s\"'`<>)]+")


class ScanError(Exception):
    pass


@dataclass
class Finding:
    rule: str
    category: str
    weight: float
    file: str
    line: int
    end_line: int
    snippet: str

    def to_dict(self) -> dict:
        return asdict(self)


def _semgrep_bin() -> str:
    explicit = os.environ.get("SEMGREP_BIN")
    if explicit:
        return explicit
    found = shutil.which("semgrep")
    if found:
        return found
    beside_python = Path(sys.executable).parent / ("semgrep.exe" if os.name == "nt" else "semgrep")
    if beside_python.exists():
        return str(beside_python)
    raise ScanError("semgrep not found; install it or set SEMGREP_BIN")


def _site(host: str) -> str:
    """Rough registrable domain: the last two labels, or the host itself for IPs and localhost."""
    host = (host or "").lower()
    if host.replace(".", "").isdigit() or "." not in host:
        return host
    return ".".join(host.split(".")[-2:])


def _is_same_site(snippet: str, page_url: str) -> bool:
    match = URL_RE.search(snippet)
    if not match or not page_url:
        return False
    return _site(urlparse(match.group()).hostname or "") == _site(urlparse(page_url).hostname or "")


def _read_lines(path: Path, start: int, end: int) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[start - 1 : end])


def scan_capture(capture: Capture) -> list[Finding]:
    """Return the findings for a capture, highest weight first."""
    return scan_captures([capture])[0]


def scan_captures(captures: list[Capture]) -> list[list[Finding]]:
    """Scan several captures in one Semgrep run; findings come back in the same order.

    Semgrep takes seconds to start, so one run over many captures is far
    cheaper than one run each.
    """
    if not captures:
        return []
    directories = [c.directory.resolve() for c in captures]
    cmd = [
        _semgrep_bin(), "scan",
        "--config", str(RULES_DIR),
        "--json", "--quiet", "--metrics=off",
        "--no-git-ignore",  # captures usually sit in an ignored directory
        "--exclude", MANIFEST,
        *[str(d) for d in directories],
    ]
    env = {**os.environ, "PYTHONUTF8": "1"}
    timeout = SCAN_TIMEOUT_S + 5 * len(captures)
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired as exc:
        raise ScanError("semgrep timed out") from exc
    try:
        report = json.loads(proc.stdout.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise ScanError(f"semgrep exited {proc.returncode}: {proc.stderr.decode(errors='replace')[-500:]}") from exc
    if proc.returncode not in (0, 1) and not report.get("results"):
        messages = "; ".join(e.get("message", "") for e in report.get("errors", []))
        raise ScanError(f"semgrep exited {proc.returncode}: {messages[:500]}")

    grouped: list[list[Finding]] = [[] for _ in captures]
    for result in report.get("results", []):
        metadata = result["extra"].get("metadata", {})
        path = Path(result["path"]).resolve()
        index = next((i for i, d in enumerate(directories) if path.is_relative_to(d)), None)
        if index is None:
            continue
        capture, findings = captures[index], grouped[index]
        start, end = result["start"]["line"], result["end"]["line"]
        # extra.lines needs a Semgrep login, so read the source ourselves.
        snippet = _read_lines(path, start, end)
        if metadata.get("cross_origin_only") and _is_same_site(snippet, capture.final_url):
            continue
        findings.append(
            Finding(
                rule=result["check_id"].split(".")[-1],
                category=metadata.get("threat_category", "unknown"),
                weight=float(metadata.get("weight", 0.3)),
                file=path.name,
                line=start,
                end_line=end,
                snippet=snippet.strip()[:400],
            )
        )
    for findings in grouped:
        findings.sort(key=lambda f: (-f.weight, f.file, f.line))
    return grouped
