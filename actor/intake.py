"""Join the stages: pending rows from ingestion, a verdict from the brain, then the ladder.

    python -m actor.intake                    one pass, dry run
    python -m actor.intake --live --loop      keep following the verdict table
    python -m actor.intake --scan --live      scan from here (no separate scanner worker)

Member 1 owns `incoming_threats`. Member 2's worker scans pending rows and appends its
verdict to `events`. This module acts on the VERIFIED ones and appends the outcome to the
same event: PUBLISHED_TAKEDOWN with a proof link, WITHHELD, later TAKEN_DOWN.
"""
import argparse
import json
import re
import sys
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone

import requests

from . import config, history, policy as policy_module
from .contract import DONE_STATUSES, Receipt, safe_id
from .dispatch import dispatch, print_receipts
from .ledger import Ledger, clickhouse_client
from .recheck import recheck_once

# A listing on one of these curated feeds is the independent second source that the
# Actor requires before it mails a hosting provider.
TRUSTED_FEEDS = {"urlhaus", "openphish", "threatfox"}
THREAT_TYPES = {"malware_download": "malware"}
MAX_BATCH = 25                     # the brain's /scan/batch limit
VERIFIED_BATCH = 200               # verdicts handled per pass: one read, one write each way

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


def verdicts_table() -> str:
    name = config.get("VERDICTS_TABLE", "events")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,80}", name):
        raise ValueError("VERDICTS_TABLE is not a plain table name")
    return name


EVENT_COLUMNS = ["event_id", "target_url", "timestamp", "semgrep_detected", "confidence_score",
                 "evidence", "action_status", "proof_url"]


def fetch_verified(client, limit: int = VERIFIED_BATCH) -> list:
    """Verdicts Member 2's worker marked VERIFIED and nobody has acted on yet."""
    query = (
        "SELECT e.event_id AS event_id, e.target_url AS target_url, e.timestamp AS event_time, "
        "e.semgrep_detected AS semgrep_detected, e.confidence_score AS confidence_score, "
        "e.evidence AS evidence, t.threat_type AS threat_type, t.feed_source AS feed_source "
        f"FROM (SELECT * FROM {verdicts_table()} FINAL WHERE action_status = 'VERIFIED') AS e "
        "LEFT JOIN (SELECT event_id, any(threat_type) AS threat_type, any(feed_source) AS feed_source "
        f"FROM {events_table()} GROUP BY event_id) AS t USING (event_id) "
        f"ORDER BY e.timestamp LIMIT {int(limit)}")
    return list(client.query(query).named_results())


def _version(row: dict, status: str, proof_url: str) -> list:
    when = row.get("event_time")
    if not isinstance(when, datetime):
        when = datetime.now(timezone.utc)
    return [str(row["event_id"]), str(row["target_url"]), when,
            bool(row.get("semgrep_detected")), row.get("confidence_score"), str(row.get("evidence") or ""),
            status, proof_url]


def write_back(client, row: dict, status: str, proof_url: str) -> None:
    """Append the Actor's version of the event; the newest version is the current one."""
    client.insert(verdicts_table(), [_version(row, status, proof_url)], column_names=EVENT_COLUMNS)


def run_verified(client, live: bool = False, ledger: Ledger = None, policy: dict = None,
                 skip: set = None) -> list:
    """Act on the scanner's VERIFIED verdicts and record the outcome on the same event."""
    ledger = ledger or Ledger()
    policy = policy or policy_module.load()
    receipts, outcomes = [], []
    rows = [r for r in fetch_verified(client) if skip is None or str(r["event_id"]) not in skip]
    history.prime([history._host(str(r["target_url"])) for r in rows])
    try:
        with ledger.batch():
            for row in rows:
                mine = _act(row, live, ledger, policy)
                receipts += mine
                if skip is not None:
                    skip.add(str(row["event_id"]))
                if not live:
                    continue
                done = [r for r in mine if r.status in DONE_STATUSES and not r.dry_run]
                public = [r.proof_url for r in done
                          if r.proof_url.startswith("http") and "localhost" not in r.proof_url]
                proof = (public or [r.proof_url for r in done if r.proof_url] or [""])[0]
                outcomes.append(_version(row, "PUBLISHED_TAKEDOWN" if done else "WITHHELD", proof))
    finally:        # what was handled is written back even when a later row stops the pass
        if outcomes:
            client.insert(verdicts_table(), outcomes, column_names=EVENT_COLUMNS)
    return receipts


def _act(row: dict, live: bool, ledger: Ledger, policy: dict) -> list:
    """One verified row through the ladder. A failure in here must not block the rows behind it."""
    event_id = str(row["event_id"])
    try:
        threat = str(row.get("threat_type") or "phishing")
        verdict = {
            "event_id": event_id, "target_url": row["target_url"],
            "timestamp": str(row.get("event_time") or ""),
            "semgrep_detected": row.get("semgrep_detected") is True or row.get("semgrep_detected") == 1,
            "confidence_score": row.get("confidence_score"),
            "evidence": row.get("evidence") or "",
            "threat_type": THREAT_TYPES.get(threat, threat),
            "corroborated": str(row.get("feed_source") or "").lower() in TRUSTED_FEEDS,
        }
        return dispatch(verdict, live=live, ledger=ledger, policy=policy)
    except Exception as exc:
        refusal = Receipt(safe_id(event_id), "", "", "all", 0, "", "SKIPPED", dry_run=not live,
                          detail=f"actor error, nothing sent: {type(exc).__name__}: {str(exc)[:200]}")
        ledger.append(refusal)
        return [refusal]


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


def follow_up(client, live: bool = False, ledger: Ledger = None, policy: dict = None,
              verdict_rows: bool = False) -> list:
    """Recheck acted-on targets; confirmed takedowns are written back as TAKEN_DOWN."""
    receipts = recheck_once(ledger, policy, live=live)
    confirmed = [r for r in receipts if r.status == "CONFIRMED_DOWN"]
    if live:
        set_status(client, "TAKEN_DOWN", [r.event_id for r in confirmed])
        if verdict_rows:
            for r in confirmed:
                current = list(client.query(
                    "SELECT event_id, target_url, timestamp AS event_time, semgrep_detected, "
                    f"confidence_score, evidence, proof_url FROM {verdicts_table()} FINAL "
                    "WHERE event_id = {id:String}", parameters={"id": r.event_id}).named_results())
                row = current[0] if current and current[0].get("event_id") == r.event_id else {
                    "event_id": r.event_id, "target_url": r.target_url, "semgrep_detected": True,
                    "evidence": r.detail}
                write_back(client, row, "TAKEN_DOWN", row.get("proof_url") or "")
    return receipts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--live", action="store_true", help="execute enabled channels")
    parser.add_argument("--loop", action="store_true", help="keep following the table")
    parser.add_argument("--interval", type=int, default=15)
    parser.add_argument("--rows", help="JSON file of rows to use instead of ClickHouse")
    parser.add_argument("--scan", action="store_true",
                        help="call the scanner from here instead of reading Member 2's verdict table")
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
        own_scan = args.scan or bool(args.rows)
        step = run_once if own_scan else run_verified
        receipts = step(client, args.live, ledger, policy, skip=None if args.live else seen)
        while receipts and args.live and not own_scan:      # a backlog is worked off in one go
            more = step(client, args.live, ledger, policy)
            if not more:
                break
            receipts += more
        receipts += follow_up(client, args.live, ledger, policy, verdict_rows=not own_scan)
        print_receipts(receipts) if receipts else print("nothing pending")
        if args.rows:
            for row in client.rows:
                print(f"  row {row['event_id']}: {row['takedown_status']}")
        if not args.loop:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
