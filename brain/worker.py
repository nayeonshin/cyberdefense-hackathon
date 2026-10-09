"""Poll Member 1's pending URLs, batch scan, append shared verdict rows.

    python -m brain.worker --once
    python -m brain.worker --limit 25 --interval 10

Run one worker per database. Multiple workers need an external claim/lease;
ClickHouse is not a transactional job queue.
"""
from __future__ import annotations

import argparse
import json
import logging
import time

from ingest import connect_clickhouse, ensure_schema, load_environment, table_name
from threatfeed import update_takedown_status
from .clickhouse import append_verdict, ensure_events_schema, events_table_name, get_pending_events, validate_verdict

from .pipeline import process_events, summarize

log = logging.getLogger(__name__)


def reconcile_completed(client, limit=25):
    """Repair a raw status update interrupted after the verdict was persisted."""
    ensure_events_schema(client)
    rows = client.query(f"""
        SELECT DISTINCT event_id FROM {table_name()}
        WHERE takedown_status = 'PENDING' AND event_id IN (
            SELECT event_id FROM {events_table_name()} FINAL WHERE action_status != 'PENDING'
        ) ORDER BY event_id LIMIT {{limit:UInt32}}
    """, parameters={"limit": limit}).result_rows
    for (event_id,) in rows:
        update_takedown_status("SCANNED", event_id=event_id, client=client)


def run_once(client, limit=25, *, scanner=None) -> dict:
    reconcile_completed(client, limit)
    pending = get_pending_events(limit, client=client)
    if not pending:
        return summarize([])
    listed = [row.pop("listed_on_feed") for row in pending]
    originals = [dict(row) for row in pending]
    results = (scanner or process_events)(pending, listed_on_feed=listed)
    if len(results) != len(pending):
        raise ValueError("scanner did not return one result per event")
    verdicts = []
    for original, (verdict, _findings) in zip(originals, results):
        for key in ("event_id", "target_url", "timestamp", "proof_url"):
            if verdict.get(key) != original[key]:
                raise ValueError(f"scanner changed {key}; refusing write-back")
        validate_verdict(verdict)
        verdicts.append(verdict)
    # Each successful insert disappears from the next pending query. A partial
    # write failure leaves only unwritten events pending. Raw status changes
    # happen after persistence; interrupted mutations are repaired next poll.
    for verdict in verdicts:
        append_verdict(verdict, client=client)
        update_takedown_status("SCANNED", event_id=verdict["event_id"], client=client)
    return summarize(verdicts)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--limit", type=int, default=25)
    parser.add_argument("--interval", type=float, default=10)
    args = parser.parse_args(argv)
    if not 1 <= args.limit <= 25 or not 0 < args.interval < float("inf"):
        parser.error("--limit must be 1..25 and --interval must be positive and finite")
    logging.basicConfig(level=logging.INFO)
    load_environment()
    client = connect_clickhouse()
    try:
        ensure_schema(client)
        ensure_events_schema(client)
        while True:
            try:
                print(json.dumps(run_once(client, args.limit)), flush=True)
            except Exception:
                log.exception("Scan/write-back failed; unwritten events remain pending")
                if args.once:
                    return 1
            if args.once:
                return 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
