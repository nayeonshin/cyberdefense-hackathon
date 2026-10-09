"""Read-only, evidence-derived input for the motion overview."""
from datetime import datetime, timezone

from .model import defang, parse_time, receipt_label, scan_complete, scan_label
from .presentation import timestamp_label


def _recorded(value, now):
    try:
        parsed = parse_time(value)
        return parsed if parsed and parsed <= now else None
    except (ValueError, TypeError, OverflowError):
        return None


def motion_state(record, receipts, *, simulated=False, historical=False, degraded=False, now=None):
    now = now or datetime.now(timezone.utc)
    if record is None:
        return dict(event_id="", target="No event selected", status="Waiting for ingestion",
                    tone="pending", phase="empty", confidence="—", evidence="No event evidence yet.",
                    scanner="Not recorded", stages=[], latest=0, receipt=None, replay=False,
                    duration=None, simulated=simulated, degraded=degraded)
    event, meta = record["event"], record["metadata"]
    ingested = _recorded(meta.get("ingested_at"), now)
    scanned = _recorded(meta.get("scan_completed_at"), now)
    scan = scan_label(event, meta)
    if scan != "Scan failed" and not scanned and not meta.get("scan_completed"):
        scan = "Pending scan" if not meta.get("scan_completed_at") else "Scan metadata unavailable"
    scan_ok = bool(scan_complete(meta) and scan in {"Threat detected", "No rule matched"})
    matching = sorted((r for r in receipts if r.get("event_id") == event["event_id"]
                       and r.get("target_url") == event["target_url"]
                       and r.get("dry_run") is False and _recorded(r.get("created_at"), now)),
                      key=lambda r: parse_time(r["created_at"]))
    # Fixtures may illustrate a finding but can never become execution evidence.
    live = [] if simulated else matching
    sent = next((r for r in live if r.get("status") == "SENT"), None)
    confirmed = next((r for r in live if r.get("status") == "CONFIRMED_DOWN"), None)
    last = live[-1] if live else None
    negative = scan == "No rule matched"
    status, phase = scan, {"Threat detected": "detected", "Scan failed": "scan-failed",
                           "No rule matched": "negative"}.get(scan, "pending")
    if sent:
        status, phase = "Report submitted", "submitted"
    if last and last.get("status") in {"FAILED", "SKIPPED", "SINK", "STILL_UP"}:
        status = receipt_label(last)
        phase = {"FAILED": "dispatch-failed", "SKIPPED": "skipped", "SINK": "saved-test",
                 "STILL_UP": "reachable"}[last["status"]]
    if confirmed and (not last or last.get("status") != "STILL_UP"):
        status = "Historical confirmation" if historical else "Probe-confirmed unavailability"
        phase = "historical" if historical else "confirmed"
    tone = "danger" if phase in {"detected", "scan-failed", "dispatch-failed"} else (
        "pending" if phase in {"pending", "historical", "reachable"} else "neutral")
    timestamps = [ingested, scanned if scan_ok else None,
                  parse_time(sent["created_at"]) if sent else None,
                  parse_time(confirmed["created_at"]) if confirmed else None]
    reached = [bool(t) for t in timestamps]
    reached[1] = scan_ok
    details = [timestamp_label(ingested), scan,
               "Submitted" if sent else ("Not applicable" if negative else receipt_label(last) if last else "Awaiting receipt"),
               status if confirmed else ("Not applicable" if negative else "Awaiting confirmation")]
    stages = [dict(title=title, detail=details[i], time=timestamp_label(timestamps[i]),
                   recorded=timestamps[i].isoformat() if timestamps[i] else None, reached=reached[i],
                   historical=bool(i == 3 and confirmed and historical))
              for i, title in enumerate(("Discovered", "Scanned", "Report submitted", "Unavailability confirmed"))]
    latest = max([i for i, done in enumerate(reached) if done] or [0])
    if scan == "Scan failed":
        latest = max(latest, 1)
    ordered = all(timestamps) and all(a <= b for a, b in zip(timestamps, timestamps[1:]))
    replay = bool(ordered and scan == "Threat detected" and meta.get("scanner") == "semgrep"
                  and phase == "confirmed" and not (simulated or historical or degraded))
    duration = (timestamps[-1] - timestamps[0]).total_seconds() if ordered else None
    preview = "\n".join(event["evidence"].splitlines()[:6])[:480]
    if preview != event["evidence"]:
        preview += "\n… Full evidence below."
    return dict(event_id=event["event_id"], target=defang(event["target_url"]), status=status,
                tone=tone, phase=phase, confidence=f"{event['confidence_score']:.2f}" if scan_ok else "—",
                evidence=preview or "No completed scan evidence yet.",
                scanner=str(meta.get("scanner") or "Not recorded"), stages=stages, latest=latest,
                receipt=dict(action=sent["action"], detail=sent.get("detail", ""),
                             created_at=sent["created_at"]) if sent else None,
                replay=replay, duration=duration, simulated=simulated, degraded=degraded)
