"""Join the stages: pending rows from ingestion, a verdict from the brain, then the ladder.

    python -m actor.intake                    one pass, dry run
    python -m actor.intake --live --loop      keep following the table

Member 1 owns `incoming_threats`, Member 2 owns the scan. This module reads the first,
calls the second, hands verified threats to the Actor and writes the outcome back.
"""
import argparse
import json
import re
import sys
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone

import requests

from . import config, policy as policy_module
from .contract import DONE_STATUSES, Receipt, safe_id
from .dispatch import dispatch, print_receipts
from .ledger import Ledger, clickhouse_client
from .recheck import recheck_once

# A listing on one of these curated feeds is the independent second source that the
# Actor requires before it mails a hosting provider.
TRUSTED_FEEDS = {"urlhaus"}
THREAT_TYPES = {"malware_download": "malware"}
MAX_BATCH = 25                     # the brain's /scan/batch limit

VERDICTS_DDL = """
CREATE TABLE IF NOT EXISTS verdicts (
    event_id String,
    target_url String,
    semgrep_detected Bool,
    confidence_score Float64,
    evidence String,
    action_status LowCardinality(String),
    findings String,
    scanned_at DateTime64(3, 'UTC')
) ENGINE = MergeTree ORDER BY (scanned_at, event_id)
"""
VERDICT_COLUMNS = ["event_id", "target_url", "semgrep_detected", "confidence_score", "evidence",
                   "action_status", "findings", "scanned_at"]


class LocalTable:
    """Rows from a JSON file standing in for the ClickHouse table, for runs without a database."""

    def __init__(self, rows: list):
        self.rows = [dict({"takedown_status": "PENDING", "feed_source": "", "threat_type": ""}, **r)
                     for r in rows]

    def query(self, sql, parameters=None):
        pending = [dict(r) for r in self.rows if r["takedown_status"] == "PENDING"]

        class Result:
            @staticmethod
            def named_results():
                return pending
        return Result()

    def command(self, sql, parameters=None):
        match = re.search(r"takedown_status = '([A-Z_]+)'", sql)
        if match and parameters:
            for row in self.rows:
                if row["event_id"] in parameters["ids"]:
                    row["takedown_status"] = match.group(1)

    def insert(self, table, data, column_names=None):
        pass


def events_table() -> str:
    name = config.get("EVENTS_TABLE", "incoming_threats")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,80}", name):
        raise ValueError("EVENTS_TABLE is not a plain table name")
    return name


def fetch_pending(client, limit: int = MAX_BATCH) -> list:
    query = (f"SELECT event_id, target_url, toString(`timestamp`) AS timestamp, threat_type, "
             f"feed_source FROM {events_table()} WHERE takedown_status = 'PENDING' "
             f"ORDER BY `timestamp` DESC LIMIT {int(limit)}")
    return list(client.query(query).named_results())


def set_status(client, status: str, event_ids: list) -> None:
    """One synchronous mutation per status, as Member 1's contract asks."""
    if not event_ids:
        return
    client.command(
        f"ALTER TABLE {events_table()} UPDATE takedown_status = '{status}' "
        "WHERE event_id IN {ids:Array(String)} SETTINGS mutations_sync = 1",
        parameters={"ids": list(event_ids)})


def scan(events: list) -> list:
    """Ask Member 2's brain. Over HTTP when BRAIN_URL is set, otherwise in process."""
    url = config.get("BRAIN_URL")
    if url:
        key = config.get("BRAIN_API_KEY")
        response = requests.post(url.rstrip("/") + "/scan/batch", json={"events": events},
                                 headers={"X-API-Key": key} if key else {}, timeout=180)
        response.raise_for_status()
        return response.json()["results"]
    from brain.pipeline import process_events
    pairs = process_events(events, [bool(e.get("listed_on_feed")) for e in events])
    return [dict(event, findings=[asdict(f) if is_dataclass(f) else dict(f) for f in findings])
            for event, findings in pairs]


def to_event(row: dict) -> dict:
    """A table row in the team's shared contract, as the brain expects it."""
    return {
        "event_id": str(row["event_id"]), "target_url": str(row["target_url"]),
        "timestamp": str(row.get("timestamp", "")), "action_status": "PENDING",
        "listed_on_feed": str(row.get("feed_source", "")).lower() in TRUSTED_FEEDS,
    }


def to_verdict(row: dict, result: dict) -> dict:
    """The brain's answer as a verdict for the Actor. Raises ValueError when it does not fit."""
    if not isinstance(result, dict):
        raise ValueError("brain result is not an object")
    if str(result.get("event_id")) != str(row["event_id"]) or \
            result.get("target_url") != row["target_url"]:
        raise ValueError("brain answered for a different event")
    threat = str(row.get("threat_type") or "phishing")
    return {
        "event_id": str(row["event_id"]),
        "target_url": row["target_url"],
        "timestamp": str(row.get("timestamp", "")),
        # Only a verdict the brain itself marked VERIFIED counts as a detection.
        "semgrep_detected": result.get("semgrep_detected") is True
        and result.get("action_status") == "VERIFIED",
        "confidence_score": result.get("confidence_score"),
        "evidence": result.get("evidence") or "",
        "threat_type": THREAT_TYPES.get(threat, threat),
        "corroborated": str(row.get("feed_source", "")).lower() in TRUSTED_FEEDS,
    }


def record_verdict(client, row: dict, result: dict) -> None:
    try:
        confidence = float(result.get("confidence_score") or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    client.insert("verdicts", [[
        str(row["event_id"]), str(row["target_url"]), result.get("semgrep_detected") is True,
        confidence, str(result.get("evidence") or "")[:4000],
        str(result.get("action_status") or ""), json.dumps(result.get("findings") or [])[:20000],
        datetime.now(timezone.utc)]], column_names=VERDICT_COLUMNS)


def run_once(client, live: bool = False, ledger: Ledger = None, policy: dict = None,
             skip: set = None) -> list:
    """One pass over the pending rows. Returns every receipt written."""
    ledger = ledger or Ledger()
    policy = policy or policy_module.load()
    rows = [r for r in fetch_pending(client) if str(r["event_id"]) not in (skip or set())]
    if not rows:
        return []
    try:
        results = scan([to_event(r) for r in rows])
        if not isinstance(results, list) or len(results) != len(rows):
            raise ValueError(f"brain returned {len(results) if isinstance(results, list) else 'no'} "
                             f"results for {len(rows)} events")
    except Exception as exc:        # rows stay PENDING and are retried on the next pass
        print(f"[intake] scan failed, nothing acted on: {type(exc).__name__}: {exc}", file=sys.stderr)
        return []

    receipts, reported, scanned = [], [], []
    for row, result in zip(rows, results):
        event_id = str(row["event_id"])
        try:
            verdict = to_verdict(row, result)
        except ValueError as exc:   # the brain's fault, not the row's: leave it PENDING
            refusal = Receipt(safe_id(event_id), "", "", "all", 0, "", "SKIPPED",
                              dry_run=not live, detail=f"brain result refused: {exc}")
            ledger.append(refusal)
            receipts.append(refusal)
            continue
        if live:
            try:
                record_verdict(client, row, result)
            except Exception as exc:
                print(f"[intake] verdict not stored: {exc}", file=sys.stderr)
        mine = dispatch(verdict, live=live, ledger=ledger, policy=policy)
        receipts += mine
        acted = any(r.status in DONE_STATUSES and not r.dry_run for r in mine)
        (reported if acted else scanned).append(event_id)
        if skip is not None:
            skip.add(event_id)
    if live:
        set_status(client, "REPORTED", reported)
        set_status(client, "SCANNED", scanned)
    return receipts


def follow_up(client, live: bool = False, ledger: Ledger = None, policy: dict = None) -> list:
    """Recheck acted-on targets; confirmed takedowns are written back as TAKEN_DOWN."""
    receipts = recheck_once(ledger, policy, live=live)
    if live:
        set_status(client, "TAKEN_DOWN",
                   [r.event_id for r in receipts if r.status == "CONFIRMED_DOWN"])
    return receipts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--live", action="store_true", help="execute enabled channels")
    parser.add_argument("--loop", action="store_true", help="keep following the table")
    parser.add_argument("--interval", type=int, default=15)
    parser.add_argument("--rows", help="JSON file of rows to use instead of ClickHouse")
    args = parser.parse_args()

    if args.rows:
        with open(args.rows, encoding="utf-8") as handle:
            client = LocalTable(json.load(handle))
    else:
        client = clickhouse_client()
        if client is None:
            sys.exit("CLICKHOUSE_HOST and CLICKHOUSE_PASSWORD must be set in .env, or pass --rows")
        client.command(VERDICTS_DDL)
    ledger, policy, seen = Ledger(), policy_module.load(), set()
    print("LIVE: enabled channels will send" if args.live else "DRY RUN: nothing is sent")
    while True:
        receipts = run_once(client, args.live, ledger, policy, skip=None if args.live else seen)
        receipts += follow_up(client, args.live, ledger, policy)
        print_receipts(receipts) if receipts else print("nothing pending")
        if args.rows:
            for row in client.rows:
                print(f"  row {row['event_id']}: {row['takedown_status']}")
        if not args.loop:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
