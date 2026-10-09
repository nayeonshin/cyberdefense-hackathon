"""Read-only data adapters. A failed live connection never substitutes fixtures."""
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .model import FIELDS, parse_time, validate_event
from .storage import read_json, read_jsonl


def calculate_metrics(records, receipts):
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=1)
    times = [parse_time(r["metadata"].get("ingested_at")) for r in records]
    return {"ingested_per_minute": sum(t is not None and cutoff <= t <= now for t in times),
            "total_events": len(records),
            "pending_scans": sum(not r["metadata"].get("scan_completed_at") for r in records),
            "detected": sum(r["event"]["semgrep_detected"] and bool(r["metadata"].get("scan_completed_at")) for r in records),
            "submitted_actions": sum(r.get("status") == "SENT" and not r.get("dry_run", True) for r in receipts)}


class FileSource:
    simulated = False

    def __init__(self, settings):
        self.settings = settings

    def get_events(self):
        records = read_json(self.settings.run_dir / "events.json", [])
        return [{"event": validate_event(r["event"]), "metadata": dict(r.get("metadata", {}))} for r in records]

    def get_receipts(self, event_id=None):
        rows = read_jsonl(self.settings.run_dir / "actions.jsonl")
        return sorted([r for r in rows if event_id is None or r["event_id"] == event_id],
                      key=lambda r: r["created_at"], reverse=True)

    def get_metrics(self):
        return calculate_metrics(self.get_events(), self.get_receipts())


class FixtureSource(FileSource):
    simulated = True

    def __init__(self, settings):
        super().__init__(settings)
        self.fixture = read_json(Path(__file__).parent.parent / "fixtures" / "dashboard.json")

    def get_events(self):
        return [{"event": validate_event(r["event"]), "metadata": dict(r["metadata"])} for r in self.fixture["records"]]

    def get_receipts(self, event_id=None):
        return [r for r in self.fixture["receipts"] if event_id is None or r["event_id"] == event_id]


def identifier(value):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        raise ValueError("ClickHouse table names must be plain SQL identifiers")
    return value


def clickhouse_client():
    import clickhouse_connect
    if not os.getenv("CLICKHOUSE_HOST"):
        raise ValueError("CLICKHOUSE_HOST is required for live ClickHouse mode")
    return clickhouse_connect.get_client(host=os.environ["CLICKHOUSE_HOST"],
        port=int(os.getenv("CLICKHOUSE_PORT", "8443")),
        username=os.getenv("CLICKHOUSE_USER", "default"), password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        database=os.getenv("CLICKHOUSE_DATABASE", "default"),
        secure=os.getenv("CLICKHOUSE_SECURE", "1") == "1", connect_timeout=5, send_receive_timeout=10)


class ClickHouseSource:
    simulated = False

    def __init__(self, settings, client=None):
        self.settings = settings
        self.client = client or clickhouse_client()
        self.table = identifier(os.getenv("EVENTS_TABLE", "incoming_threats"))

    def _query(self, sql, parameters=None):
        return list(self.client.query(sql, parameters=parameters).named_results())

    def get_events(self):
        rows = self._query(f"SELECT {', '.join(FIELDS)}, ingested_at, scan_completed_at, scanner, run_id "
                           f"FROM {self.table} WHERE run_id = {{run:String}} ORDER BY ingested_at DESC LIMIT 200",
                           {"run": self.settings.run_id})
        result = []
        for row in rows:
            event = {k: row[k] for k in FIELDS}
            event["timestamp"] = parse_time(event["timestamp"]).isoformat()
            event["semgrep_detected"] = bool(event["semgrep_detected"])
            event["confidence_score"] = float(event["confidence_score"])
            metadata = {k: row[k] for k in ("ingested_at", "scan_completed_at", "scanner", "run_id")}
            result.append({"event": validate_event(event), "metadata": metadata})
        return result

    def get_receipts(self, event_id=None):
        params = {"run": self.settings.run_id}
        where = f"event_id IN (SELECT event_id FROM {self.table} WHERE run_id = {{run:String}})"
        if event_id is not None:
            where += " AND event_id = {event:String}"
            params["event"] = event_id
        rows = self._query(f"SELECT * FROM actions WHERE {where} ORDER BY created_at DESC LIMIT 200", params)
        for row in rows:
            row["created_at"] = parse_time(row["created_at"]).isoformat()
        return rows

    def get_metrics(self):
        values = self._query(f"SELECT count() AS total_events, "
            "countIf(ingested_at >= now64(3) - INTERVAL 1 MINUTE AND ingested_at <= now64(3)) AS ingested_per_minute, "
            "countIf(scan_completed_at IS NULL) AS pending_scans, "
            "countIf(semgrep_detected AND scan_completed_at IS NOT NULL) AS detected "
            f"FROM {self.table} WHERE run_id = {{run:String}}", {"run": self.settings.run_id})[0]
        actions = self._query("SELECT count() AS submitted_actions FROM actions WHERE status = 'SENT' AND NOT dry_run "
            f"AND event_id IN (SELECT event_id FROM {self.table} WHERE run_id = {{run:String}})", {"run": self.settings.run_id})[0]
        return {**values, **actions}

    def close(self):
        self.client.close()


def make_source(settings):
    return {"fixtures": FixtureSource, "files": FileSource, "clickhouse": ClickHouseSource}[settings.source](settings)
