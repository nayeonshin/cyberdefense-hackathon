"""Shared data contract between ingestion, verdict and action stages."""
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from urllib.parse import urlparse


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass
class Verdict:
    event_id: str
    target_url: str
    timestamp: str = ""
    semgrep_detected: bool = False
    confidence_score: float = 0.0
    evidence: str = ""
    action_status: str = "PENDING"
    proof_url: str = ""
    # Optional extras. Missing keys keep these defaults, so the team contract stays valid.
    threat_type: str = "phishing"
    corroborated: bool = False   # a second, independent source confirmed the threat
    controlled: bool = False     # a target the team owns, used for the on-stage loop
    simulated: bool = False      # fixture data: planned only, never sent, even with --live

    @classmethod
    def from_dict(cls, data: dict) -> "Verdict":
        known = {f.name for f in fields(cls)}
        clean = {k: v for k, v in data.items() if k in known}
        verdict = cls(**clean)
        verdict.semgrep_detected = bool(verdict.semgrep_detected)
        verdict.confidence_score = float(verdict.confidence_score)
        return verdict

    @property
    def host(self) -> str:
        return (urlparse(self.target_url).hostname or "").lower()


@dataclass
class Receipt:
    event_id: str
    target_url: str
    domain: str
    action: str
    rung: int
    recipient: str
    status: str            # PLANNED, SENT, SINK, SKIPPED, FAILED, STILL_UP, CONFIRMED_DOWN
    proof_url: str = ""
    evidence_sha256: str = ""
    dry_run: bool = True
    latency_ms: int = 0
    detail: str = ""
    created_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict:
        return asdict(self)


DONE_STATUSES = ("SENT", "SINK")
