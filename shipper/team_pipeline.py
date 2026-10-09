"""Controlled integration adapter for the unmodified Member 1 and Member 2 code.

This discovers only the bundled owned target. It never polls or scans public
threat feeds. File mode is real Semgrep execution but is not ClickHouse usage.
"""
import os
import signal
import threading
from datetime import datetime, timezone

import requests
from filelock import FileLock

import ingest
from brain.fetcher import fetch_target
from brain.scan import scan_capture
from brain.decide import decide
from .data import ClickHouseSource, clickhouse_client
from .model import FIELDS, now_iso, parse_time, validate_event
from .settings import Settings
from .storage import read_json, write_json

META = ("ingested_at", "scan_completed_at", "scanner", "run_id")
DDL = """CREATE TABLE IF NOT EXISTS shipper_event_versions (
    event_id String, target_url String, timestamp DateTime64(3, 'UTC'),
    semgrep_detected Bool, confidence_score Float64, evidence String,
    action_status String, proof_url String, ingested_at DateTime64(3, 'UTC'),
    scan_completed_at Nullable(DateTime64(3, 'UTC')), scanner String,
    run_id String, version UInt64
) ENGINE = ReplacingMergeTree(version) ORDER BY (run_id, event_id)"""
VIEW = """CREATE VIEW IF NOT EXISTS shipper_events AS
SELECT event_id, target_url, timestamp, semgrep_detected, confidence_score,
evidence, action_status, proof_url, ingested_at, scan_completed_at, scanner, run_id
FROM shipper_event_versions FINAL"""


class TeamPipeline:
    def __init__(self, settings):
        if settings.mode != "controlled" or settings.source == "fixtures":
            raise ValueError("Team pipeline requires controlled mode and files or ClickHouse")
        self.settings = settings
        self.path = settings.run_dir / "events.json"
        self.client = None
        self.initialized = False

    def initialize(self):
        if self.initialized:
            return
        if self.settings.source == "clickhouse":
            if os.getenv("EVENTS_TABLE") != "shipper_events":
                raise ValueError("Set EVENTS_TABLE=shipper_events for the Member 1 adapter")
            self.client = clickhouse_client()
            # Member 1 owns this schema; never alter or recreate an existing table.
            ingest.ensure_schema(self.client)
            self.client.command(DDL)
            self.client.command(VIEW)
        self.initialized = True

    def publish(self, record):
        validate_event(record["event"])
        if self.client:
            event, meta = record["event"], record["metadata"]
            values = [event[k] for k in FIELDS] + [meta.get(k) for k in META]
            for index in (2, 8, 9):
                values[index] = parse_time(values[index])
            # Failure/retry updates need new versions without changing ingestion time.
            version = int(datetime.now(timezone.utc).timestamp() * 1_000_000)
            self.client.insert("shipper_event_versions", [values + [version]],
                               column_names=list(FIELDS) + list(META) + ["version"])
        write_json(self.path, [record])

    def discover(self):
        response = requests.get(self.settings.controlled_url, timeout=5, allow_redirects=False)
        response.raise_for_status()
        if response.status_code != 200 or "Team-owned harmless scan target" not in response.text:
            raise ValueError("Owned target is unavailable or not the expected controlled page")
        stamp = now_iso()
        event = {"event_id": "controlled-" + self.settings.run_id,
            "target_url": self.settings.controlled_url, "timestamp": stamp,
            "semgrep_detected": False, "confidence_score": 0.0, "evidence": "",
            "action_status": "PENDING", "proof_url": ""}
        ingested_at = stamp
        if self.client:
            # Real owned-target observation, explicitly distinct from the URLhaus feed.
            rows = [(event["event_id"], event["target_url"],
                ingest.derive_domain("localhost", event["target_url"]), "127.0.0.1",
                parse_time(stamp), "controlled_demonstration", "PENDING", "controlled_owned_target")]
            fresh, _ = ingest.drop_duplicates(self.client, rows)
            ingest.insert_rows(self.client, fresh)
            raw = self.client.query("SELECT first_seen FROM incoming_threats WHERE event_id={id:String} LIMIT 1",
                                    parameters={"id": event["event_id"]}).first_row
            ingested_at = parse_time(raw[0]).isoformat()
        record = {"event": event, "metadata": {"ingested_at": ingested_at,
            "scan_completed_at": None, "scanner": "", "run_id": self.settings.run_id}}
        self.publish(record)
        return record

    def tick(self):
        self.initialize()
        records = read_json(self.path, [])
        if self.client:
            persisted = ClickHouseSource(self.settings, self.client).get_events()
            if persisted:
                records = persisted
        if not records:
            self.discover()
            return "Owned target discovered; waiting for actual Semgrep scan."
        if len(records) != 1:
            raise ValueError("Controlled adapter requires one event per deliberate run")
        record = records[0]
        event, metadata = record["event"], record["metadata"]
        if event["target_url"] != self.settings.controlled_url or metadata["run_id"] != self.settings.run_id:
            raise ValueError("Refusing an event outside this owned run")
        if metadata.get("scan_completed_at"):
            return "Actual Semgrep scan completed; awaiting or preserving Actor receipts."
        # Only this process receives the demo fetch flag; its only input is the
        # exact owned localhost URL above. Public target scanning is not enabled.
        os.environ["BRAIN_ALLOW_PRIVATE"] = "1"
        capture_dir = self.settings.run_dir / "capture"
        capture = fetch_target(event["target_url"], capture_dir)
        if not capture.ok:
            record["event"] = {**event, "action_status": "FETCH_FAILED", "evidence": "Owned target fetch failed."}
            record["metadata"]["scan_error"] = "Fetch failed; no completed scan."
            self.publish(record)
            raise RuntimeError("Controlled fetch failed")
        try:
            findings = scan_capture(capture)
        except Exception:
            record["event"] = {**event, "action_status": "SCAN_FAILED", "evidence": "Semgrep did not complete."}
            record["metadata"]["scan_error"] = "Semgrep execution failed; retry pending."
            self.publish(record)
            raise
        result = validate_event(decide(event, capture, findings, listed_on_feed=False))
        completed_at = now_iso()
        write_json(self.settings.run_dir / "scan-findings.json", {
            "event_id": event["event_id"], "scanner": "semgrep", "completed_at": completed_at,
            "findings": [finding.to_dict() for finding in findings], "controlled": True,
            "source_branch": "timothy", "source_commit": "3e55a3ecaeef1ab1a2bbd96c93852ce92bf80bd7"})
        record = {"event": result, "metadata": {**metadata, "scan_completed_at": completed_at,
                   "scanner": "semgrep", "scan_error": ""}}
        self.publish(record)
        return "Actual Semgrep completed: " + str(len(findings)) + " finding(s)."

    def close(self):
        if self.client:
            self.client.close()


def main():
    settings = Settings.from_env()
    settings.run_dir.mkdir(parents=True, exist_ok=True)
    stop = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stop.set())
    with FileLock(str(settings.run_dir / "team-pipeline.lock"), timeout=0):
        pipeline = TeamPipeline(settings)
        try:
            while not stop.is_set():
                try:
                    detail = pipeline.tick()
                    status = "running"
                except Exception as exc:
                    detail = type(exc).__name__ + ": team integration unavailable; retrying."
                    status = "degraded"
                write_json(settings.run_dir / "pipeline.json", {"status": status, "detail": detail,
                    "updated_at": now_iso(), "run_id": settings.run_id})
                stop.wait(2 if status == "running" else 10)
        finally:
            pipeline.close()


if __name__ == "__main__":
    main()
