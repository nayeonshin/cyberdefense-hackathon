"""Acceptance probe for a real controlled run; never mutates pipeline state."""
import argparse
import json
import time

from .model import current_confirmation, parse_time
from .settings import Settings
from .storage import read_json, read_jsonl, write_json


def inspect_run(settings, previous_started_at=None):
    records = read_json(settings.run_dir / "events.json", [])
    findings = read_json(settings.run_dir / "scan-findings.json", {})
    receipts = read_jsonl(settings.run_dir / "actions.jsonl")
    check = read_json(settings.run_dir / "target-check.json", {})
    heartbeat = read_json(settings.run_dir / "heartbeat.json", {})
    if heartbeat.get("status") != "running":
        return None  # A recent saved check alone does not prove worker recovery.
    if previous_started_at and heartbeat.get("started_at") == previous_started_at:
        return None  # Wait for this restart's worker, not the old files on disk.
    if not records or not findings.get("findings"):
        return None
    event, meta = records[0]["event"], records[0]["metadata"]
    matching = [r for r in receipts if r["event_id"] == event["event_id"]
                and r["target_url"] == event["target_url"] and not r["dry_run"]]
    sent = [r for r in matching if r["action"] == "mock_registrar" and r["status"] == "SENT"]
    confirmed = [r for r in matching if r["status"] == "CONFIRMED_DOWN"]
    if len(sent) > 1:
        raise RuntimeError("Duplicate controlled dispatch detected")
    fresh = current_confirmation(check, heartbeat)
    if (not sent or not confirmed or not fresh or check.get("http_status") != 410
        or check.get("started_at") != heartbeat.get("started_at")):
        return None
    if findings["event_id"] != event["event_id"] or meta.get("scanner") != "semgrep":
        raise RuntimeError("Scan evidence does not match the event")
    database_verified = False
    if settings.source == "clickhouse":
        from .data import ClickHouseSource
        source = ClickHouseSource(settings)
        try:
            database_events = source.get_events()
            database_receipts = source.get_receipts(event["event_id"])
            metrics = source.get_metrics()
            database_verified = (len(database_events) == 1
                and database_events[0]["event"]["event_id"] == event["event_id"]
                and bool(database_events[0]["metadata"].get("scan_completed_at"))
                and any(r["status"] == "CONFIRMED_DOWN" for r in database_receipts)
                and metrics["submitted_actions"] == 1 and metrics["detected"] == 1)
        finally:
            source.close()
        if not database_verified:
            return None  # The worker may still be flushing its durable receipts.
    elapsed = (parse_time(confirmed[0]["created_at"]) - parse_time(meta["ingested_at"])).total_seconds()
    return {"run_id": settings.run_id, "event_id": event["event_id"], "controlled": True,
        "scanner": "semgrep", "findings": len(findings["findings"]), "submitted_receipts": len(sent),
        "confirmed_suspension": True, "http_status": 410, "elapsed_seconds": round(elapsed, 3),
        "within_recording_window": 0 <= elapsed <= 180, "data_source": settings.source,
        "clickhouse_verified": database_verified, "checked_at": check["checked_at"],
        "worker_started_at": heartbeat["started_at"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wait", type=int, default=150)
    parser.add_argument("--output")
    parser.add_argument("--previous-started-at")
    args = parser.parse_args()
    settings = Settings.from_env()
    if settings.mode != "controlled" or settings.source == "fixtures":
        raise SystemExit("A real controlled run is required")
    deadline = time.monotonic() + args.wait
    while time.monotonic() < deadline:
        result = inspect_run(settings, args.previous_started_at)
        if result:
            if not result["within_recording_window"]:
                raise SystemExit("Controlled run exceeded 180 seconds")
            if args.output:
                write_json(args.output, result)
            print(json.dumps(result, indent=2))
            return
        time.sleep(2)
    raise SystemExit("Controlled run did not reach a fresh confirmed suspension within the wait limit")


if __name__ == "__main__":
    main()
