"""Evidence bundle with a stable hash, so every report can be checked against the feed."""
import hashlib
import json

from .contract import Verdict
from .enrich import Enrichment


def defang(text: str) -> str:
    """Make a URL or domain unclickable for human-readable pages."""
    return text.replace("http", "hxxp").replace(".", "[.]")


def build(verdict: Verdict, enrichment: Enrichment) -> dict:
    return {
        "schema": "takedown-evidence/1",
        "event_id": verdict.event_id,
        "target_url": verdict.target_url,
        "domain": verdict.host,
        "threat_type": verdict.threat_type,
        "observed_at": verdict.timestamp,
        "verdict": {
            "semgrep_detected": verdict.semgrep_detected,
            "confidence_score": verdict.confidence_score,
            "evidence": verdict.evidence,
            "corroborated": verdict.corroborated,
        },
        "infrastructure": {
            "ips": enrichment.ips,
            "registrar": enrichment.registrar,
            "host_network": enrichment.host_network,
        },
    }


def digest(bundle: dict) -> str:
    canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()
