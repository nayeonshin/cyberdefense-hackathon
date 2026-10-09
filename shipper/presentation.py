"""Pure presentation projections; no worker imports or side effects."""
from html import escape

from .model import parse_time, receipt_label, scan_label


def resolve_selection(ids, selected=None, requested=None):
    if not ids:
        return None, bool(selected)
    if selected in ids:
        return selected, False
    if selected is None and requested in ids:
        return requested, False
    return ids[0], selected is not None


def accept_queue_selection(state):
    """Translate indices against the previously rendered rows, before refresh."""
    rows = state.get("threat_queue", {}).get("selection", {}).get("rows", [])
    ids = state.get("queue_event_ids", [])
    if rows and 0 <= rows[0] < len(ids):
        state["selected_event"] = ids[rows[0]]


def timestamp_label(value):
    try:
        parsed = parse_time(value)
        return parsed.strftime("%H:%M:%S UTC") if parsed else "Not recorded"
    except (TypeError, ValueError):
        return "Not recorded"


def receipt_state(receipt, historical=False):
    label = receipt_label(receipt)
    if historical and receipt.get("status") == "CONFIRMED_DOWN" and not receipt.get("dry_run", True):
        return label + " (historical)"
    return label


def status_tone(label):
    if label in {"Threat detected", "Scan failed", "Failed"}:
        return "danger"
    if label in {"Pending scan", "Awaiting action", "Planned", "Still reachable"} or "historical" in label:
        return "pending"
    return "neutral"


def timeline(record, receipts, *, historical=False):
    event, meta = record["event"], record["metadata"]
    # Never promote fixture/dry-run receipts into executed stages.
    live = sorted((r for r in receipts if r.get("event_id") == event["event_id"]
                   and not r.get("dry_run", True)), key=lambda r: r.get("created_at", ""))
    sent = next((r for r in live if r.get("status") == "SENT"), None)
    confirmed = next((r for r in live if r.get("status") == "CONFIRMED_DOWN"), None)
    latest = live[-1] if live else None
    scan = scan_label(event, meta)
    negative = scan == "No rule matched"
    submitted_detail = "Not applicable" if negative else "Awaiting receipt"
    submitted_tone = "neutral" if negative else "pending"
    if latest and not sent:
        submitted_detail = receipt_label(latest)
        submitted_tone = status_tone(submitted_detail)
    return [
        {"title": "Discovered", "detail": timestamp_label(meta.get("ingested_at")),
         "tone": "neutral" if meta.get("ingested_at") else "pending"},
        {"title": "Scanned", "detail": scan,
         "time": timestamp_label(meta.get("scan_completed_at")), "tone": status_tone(scan)},
        {"title": "Report submitted", "detail": timestamp_label(sent.get("created_at")) if sent else submitted_detail,
         "tone": "neutral" if sent else submitted_tone},
        {"title": "Unavailability confirmed",
         "detail": ("Historical confirmation" if historical else timestamp_label(confirmed.get("created_at")))
                    if confirmed else ("Not applicable" if negative else "Awaiting confirmation"),
         "tone": "pending" if (confirmed and historical) or (not confirmed and not negative) else "neutral"},
    ]


def timeline_html(stages):
    items = []
    for number, stage in enumerate(stages, 1):
        tone = stage["tone"] if stage["tone"] in {"danger", "pending", "neutral"} else "neutral"
        extra = f'<span>{escape(stage["time"])}</span>' if stage.get("time") != "Not recorded" and stage.get("time") else ""
        items.append(f'<li class="{tone}"><span class="step-number">{number:02}</span>'
                     f'<div class="step-title">{escape(stage["title"])}</div>'
                     f'<span>{escape(stage["detail"])}</span>{extra}</li>')
    return '<ol class="pipeline-timeline" aria-label="Event progress">' + "".join(items) + '</ol>'


def metrics_html(metrics):
    fields = [("Ingested / minute", "ingested_per_minute"), ("Events", "total_events"),
              ("Pending scans", "pending_scans"), ("Detections", "detected"), ("Submitted actions", "submitted_actions")]
    return '<div class="metrics-strip" aria-label="Pipeline metrics">' + "".join(
        f'<div><span>{escape(label)}</span><strong>{escape(str(metrics[key]))}</strong></div>'
        for label, key in fields) + '</div>'
