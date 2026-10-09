"""Member 1's import interface, plus the per-event handoff to the Brain.

Raw feed rows stay in incoming_threats. Scanner and Actor versions live in
events; pending queries exclude IDs with a completed shared-contract verdict.
"""
from __future__ import annotations

import math
import os
from contextlib import contextmanager
from datetime import datetime, timezone

from ingest import connect_clickhouse, load_environment, parse_timestamp, table_name

EVENT_COLUMNS = (
    "event_id", "target_url", "timestamp", "semgrep_detected",
    "confidence_score", "evidence", "action_status", "proof_url",
)
SCANNER_STATUSES = {"VERIFIED", "REJECTED", "FETCH_FAILED"}
EVENTS_DDL = """
CREATE TABLE IF NOT EXISTS {table} (
    event_id String,
    target_url String,
    timestamp DateTime64(3, 'UTC'),
    semgrep_detected Nullable(Bool),
    confidence_score Nullable(Float64),
    evidence String DEFAULT '',
    action_status LowCardinality(String) DEFAULT 'PENDING',
    proof_url String DEFAULT '',
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(updated_at) ORDER BY event_id
"""
PENDING_WHERE = """
    takedown_status = 'PENDING'
    AND event_id NOT IN (
        SELECT event_id FROM {events} FINAL WHERE action_status != 'PENDING'
    )
"""


def events_table_name():
    # VERDICTS_TABLE matches actor/intake.py. Not EVENTS_TABLE: the Actor uses that
    # name for the raw feed table.
    return table_name(os.getenv("VERDICTS_TABLE", "events"))


def ensure_events_schema(client) -> None:
    client.command(EVENTS_DDL.format(table=events_table_name()))


def migrate_events_schema(client) -> None:
    """Widen a table created while confidence_score was Float32. Run once at worker start.

    Float32 returns 0.95 as 0.94999999, which fails a ">= 0.95" threshold downstream.
    Scores are written with two decimals, so rounding restores them exactly.
    """
    table = events_table_name()
    column = client.query(
        "SELECT type FROM system.columns WHERE database = currentDatabase() "
        "AND table = {table:String} AND name = 'confidence_score'",
        parameters={"table": table},
    ).result_rows
    if column and "Float32" in column[0][0]:
        client.command(f"ALTER TABLE {table} MODIFY COLUMN confidence_score Nullable(Float64)",
                       settings={"mutations_sync": 1})
        client.command(f"ALTER TABLE {table} UPDATE confidence_score = round(confidence_score, 2) WHERE 1",
                       settings={"mutations_sync": 1})


@contextmanager
def _connection(client=None):
    owned = client is None
    if owned:
        load_environment()
        client = connect_clickhouse()
    try:
        yield client
    finally:
        if owned:
            client.close()


def _limit(limit):
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
        raise ValueError("limit must be an integer between 1 and 1000")


def _utc(value):
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    if isinstance(value, int):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    parsed = parse_timestamp(value)
    if parsed is None:
        raise ValueError("invalid event timestamp")
    return parsed


def get_pending_events(limit: int = 25, *, client=None) -> list[dict]:
    """Return full events plus a feed-confirmation flag, not bare domains.

    Duplicate raw IDs collapse before the batch is scanned. A persisted verdict
    excludes the ID immediately, even before background MergeTree merges.
    """
    _limit(limit)
    with _connection(client) as db:
        ensure_events_schema(db)
        rows = db.query(f"""
            SELECT event_id, argMax(target_url, timestamp) AS url,
                   toUnixTimestamp(max(timestamp)) AS seen, argMax(feed_source, timestamp) AS source
            FROM {table_name()} WHERE {PENDING_WHERE.format(events=events_table_name())}
            GROUP BY event_id ORDER BY seen, event_id LIMIT {{limit:UInt32}}
        """, parameters={"limit": limit}).result_rows
    return [{
        "event_id": event_id, "target_url": url,
        "timestamp": _utc(seen).isoformat().replace("+00:00", "Z"),
        "semgrep_detected": None, "confidence_score": None, "evidence": "",
        "action_status": "PENDING", "proof_url": "",
        "listed_on_feed": source in {"urlhaus", "openphish", "threatfox"},
    } for event_id, url, seen, source in rows]


def validate_verdict(event: dict) -> None:
    for key in ("event_id", "target_url", "timestamp", "evidence", "action_status", "proof_url"):
        if not isinstance(event.get(key), str):
            raise ValueError(f"{key} must be a string")
    if not event["event_id"] or not event["target_url"]:
        raise ValueError("event_id and target_url must not be empty")
    _utc(event["timestamp"])
    if event["action_status"] not in SCANNER_STATUSES:
        raise ValueError("only completed scanner verdicts can be appended here")
    if type(event.get("semgrep_detected")) is not bool:
        raise ValueError("semgrep_detected must be a bool")
    score = event.get("confidence_score")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 0.99:
        raise ValueError("confidence_score must be finite and between 0 and 0.99")
    if event["action_status"] == "VERIFIED" and not event["semgrep_detected"]:
        raise ValueError("VERIFIED requires a scanner finding")


def append_verdict(event: dict, *, client=None) -> None:
    """Append exactly the shared fields; findings and feed flags are not stored."""
    validate_verdict(event)
    row = [event[key] for key in EVENT_COLUMNS]
    row[2] = _utc(event["timestamp"])
    with _connection(client) as db:
        ensure_events_schema(db)
        db.insert(events_table_name(), [row], column_names=list(EVENT_COLUMNS))
