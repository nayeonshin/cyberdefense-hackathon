"""Shared data contract between ingestion, verdict and action stages."""
import math
import re
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from urllib.parse import urlparse

EVENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
HOSTNAME = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?|[0-9A-Fa-f:]+")
TRUE_WORDS = {"true", "1", "yes"}
FALSE_WORDS = {"false", "0", "no", ""}


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
    def from_dict(cls, data) -> "Verdict":
        """Strict parse. Raises ValueError with the reason when the verdict is malformed."""
        if not isinstance(data, dict):
            raise ValueError("verdict is not an object")
        known = {f.name for f in fields(cls)}
        clean = {k: v for k, v in data.items() if k in known}

        event_id = clean.get("event_id")
        if not isinstance(event_id, str) or not EVENT_ID.fullmatch(event_id):
            raise ValueError("event_id must be 1-64 characters of letters, digits, . _ -")

        url = clean.get("target_url")
        if not isinstance(url, str) or not url:
            raise ValueError("target_url is missing")
        if any(ch <= " " or ord(ch) == 127 for ch in url):
            raise ValueError("target_url contains whitespace or control characters")
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").rstrip(".")
        except ValueError:
            raise ValueError("target_url does not parse") from None
        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError("target_url is not http or https")
        if not host or not HOSTNAME.fullmatch(host):
            raise ValueError("target_url has no valid host")

        clean["semgrep_detected"] = _as_bool(clean.get("semgrep_detected", False))
        try:
            confidence = float(clean.get("confidence_score", 0.0))
        except (TypeError, ValueError):
            raise ValueError("confidence_score is not a number") from None
        if not (math.isfinite(confidence) and 0.0 <= confidence <= 1.0):
            raise ValueError("confidence_score is outside 0 to 1")
        clean["confidence_score"] = confidence

        for name in ("corroborated", "controlled", "simulated"):
            if name in clean:
                clean[name] = _as_bool(clean[name])
        clean["evidence"] = str(clean.get("evidence") or "")
        timestamp = str(clean.get("timestamp") or "")
        clean["timestamp"] = "".join(ch for ch in timestamp if ch.isprintable())[:40]
        threat = re.sub(r"[^a-z0-9_-]", "-", str(clean.get("threat_type") or "phishing").lower())
        clean["threat_type"] = threat[:32] or "phishing"
        return cls(**clean)

    @property
    def host(self) -> str:
        """Lower-case host without a trailing dot."""
        return (urlparse(self.target_url).hostname or "").lower().rstrip(".")


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.strip().lower() in TRUE_WORDS | FALSE_WORDS:
        return value.strip().lower() in TRUE_WORDS
    raise ValueError(f"not a yes/no value: {str(value)[:20]!r}")


def safe_id(value) -> str:
    """A printable stand-in for an event_id that failed validation."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(value))[:64] or "invalid"


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
