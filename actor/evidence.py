"""Evidence bundle with a stable hash, so every report can be checked against the feed."""
import hashlib
import json
import re

from .contract import Verdict
from .enrich import Enrichment

SCHEME = re.compile(r"http", re.IGNORECASE)


def defang(text: str) -> str:
    """Make a URL or domain unclickable for human-readable pages."""
    return SCHEME.sub(lambda m: m.group(0)[0] + "xx" + m.group(0)[3:], text).replace(".", "[.]")


def for_people(text: str, limit: int = 2000) -> str:
    """Evidence text as it may appear in a page or mail: no live links, bounded length."""
    text = SCHEME.sub(lambda m: m.group(0)[0] + "xx" + m.group(0)[3:], text)
    return text if len(text) <= limit else text[:limit] + f" [...] ({len(text)} characters in total)"


def build(verdict: Verdict, enrichment: Enrichment, history: dict = None) -> dict:
    bundle = _base(verdict, enrichment)
    if history:
        # Earlier reports about the same host, from the ClickHouse history table.
        bundle["history"] = {k: history[k] for k in ("urls_on_record", "first_seen", "last_seen", "sources")}
    return bundle


def on_record(bundle: dict) -> str:
    """One line for a report, or an empty string when the host has no history."""
    history = bundle.get("history")
    if not history:
        return ""
    count = history["urls_on_record"]
    text = f"{count} malicious URL{'s' if count != 1 else ''} on record for this host ({history['sources']})"
    if history["first_seen"]:
        text += f", dated {history['first_seen']} to {history['last_seen']}"
    return text


def _base(verdict: Verdict, enrichment: Enrichment) -> dict:
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
