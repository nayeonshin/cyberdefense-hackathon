"""The eight-field team contract plus presentation-only metadata."""
import ipaddress
import math
from datetime import datetime, timezone
from urllib.parse import urlsplit

FIELDS = ("event_id", "target_url", "timestamp", "semgrep_detected", "confidence_score",
          "evidence", "action_status", "proof_url")


def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value):
    if not value:
        return None
    dt = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def validate_event(value):
    if set(value) != set(FIELDS):
        raise ValueError("Event must contain exactly the eight shared-contract fields")
    result = dict(value)
    if not all(isinstance(result[k], str) for k in FIELDS if k not in {"semgrep_detected", "confidence_score"}):
        raise ValueError("Contract text fields must be strings")
    if not result["event_id"] or not result["timestamp"]:
        raise ValueError("event_id and timestamp are required")
    if type(result["semgrep_detected"]) is not bool:
        raise ValueError("semgrep_detected must be a boolean, not a string")
    score = result["confidence_score"]
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 1:
        raise ValueError("confidence_score must be a finite number from 0 to 1")
    url = urlsplit(result["target_url"])
    if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password:
        raise ValueError("target_url must be an HTTP(S) URL without credentials")
    parse_time(result["timestamp"])
    return result


def defang(url):
    return str(url).replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]")


def public_proof(url):
    """Validate links without fetching or resolving any user-supplied target."""
    try:
        if any(ord(ch) < 33 for ch in str(url)) or "\\" in str(url):
            return None
        parsed = urlsplit(str(url))
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in {"http", "https"} or not host or parsed.username or parsed.password:
            return None
        if host == "localhost" or "." not in host or host.endswith((".localhost", ".local", ".internal", ".test", ".invalid")):
            return None
        try:
            if not ipaddress.ip_address(host).is_global:
                return None
        except ValueError:
            if host.replace(".", "").isdigit() or host.startswith("0x"):
                return None
        _ = parsed.port
        return str(url)
    except (ValueError, TypeError):
        return None


def scan_label(event, metadata):
    if metadata.get("scan_error") or event.get("action_status") in {"FETCH_FAILED", "SCAN_FAILED"}:
        return "Scan failed"
    if not metadata.get("scan_completed_at"):
        return "Pending scan"
    return "Threat detected" if event["semgrep_detected"] else "No rule matched"


def receipt_label(receipt):
    if receipt.get("dry_run", True):
        return "Preview only"
    return {"SENT": "Submitted", "SINK": "Saved test message", "CONFIRMED_DOWN": "Probe-confirmed unavailability",
            "PLANNED": "Planned", "SKIPPED": "Skipped", "FAILED": "Failed", "STILL_UP": "Still reachable"}.get(receipt.get("status"), "Unknown")


def current_confirmation(check, heartbeat, not_before=None):
    checked, started = parse_time(check.get("checked_at")), parse_time(heartbeat.get("started_at"))
    boundary = parse_time(not_before)
    return bool(checked and started and (not boundary or started >= boundary)
        and check.get("started_at") == heartbeat.get("started_at")
        and 0 <= (datetime.now(timezone.utc) - checked).total_seconds() < 15)
