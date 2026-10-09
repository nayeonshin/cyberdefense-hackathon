"""Turn findings into the team's shared event contract. No model involved."""
from __future__ import annotations

import os

from .fetcher import Capture
from .scan import Finding

THRESHOLD = float(os.environ.get("BRAIN_THRESHOLD", "0.6"))
FEED_BONUS = 0.15
MAX_CONFIDENCE = 0.99

PENDING = "PENDING"
VERIFIED = "VERIFIED"
REJECTED = "REJECTED"
FETCH_FAILED = "FETCH_FAILED"


def confidence(findings: list[Finding], listed_on_feed: bool = False) -> float:
    """1 - prod(1 - weight) over distinct rules, so two medium findings outrank one."""
    if not findings:
        return 0.0
    weights = {}
    for f in findings:
        weights[f.rule] = max(weights.get(f.rule, 0.0), f.weight)
    miss = 1.0
    for w in weights.values():
        miss *= 1.0 - w
    score = 1.0 - miss
    if listed_on_feed:
        score += FEED_BONUS
    return round(min(score, MAX_CONFIDENCE), 2)


def format_evidence(findings: list[Finding]) -> str:
    if not findings:
        return "No Semgrep rule matched"
    top = findings[0]
    lines = f"line {top.line}" if top.line == top.end_line else f"lines {top.line}-{top.end_line}"
    first_line = top.snippet.splitlines()[0].strip() if top.snippet else ""
    text = f"Semgrep rule `{top.rule}` matched {top.file} {lines}: {first_line[:160]}"
    others = sorted({f.rule for f in findings} - {top.rule})
    if others:
        text += f" (also matched: {', '.join(others)})"
    return text


def decide(event: dict, capture: Capture, findings: list[Finding], listed_on_feed: bool = False) -> dict:
    """Return a copy of event with Member 2's fields filled in."""
    out = dict(event)
    out.setdefault("proof_url", "")
    if not capture.ok:
        out.update(
            semgrep_detected=False,
            confidence_score=0.0,
            evidence=f"Fetch failed: {capture.error}",
            action_status=FETCH_FAILED,
        )
        return out
    score = confidence(findings, listed_on_feed)
    out.update(
        semgrep_detected=bool(findings),
        confidence_score=score,
        evidence=format_evidence(findings),
        action_status=VERIFIED if score >= THRESHOLD else REJECTED,
    )
    return out
