"""Opt-in, isolated ClickHouse tests. Never fetches live feed targets."""
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import clickhouse_connect
import pytest

import ingest
import threatfeed
from brain import clickhouse as store, telemetry, worker
from tests.test_brain import allow_private, demo_server, needs_semgrep

pytestmark = pytest.mark.skipif(os.getenv("RUN_CLICKHOUSE_TESTS") != "1",
                                reason="set RUN_CLICKHOUSE_TESTS=1 for a local ClickHouse test server")


@pytest.fixture
def database(monkeypatch):
    # New database names prevent any destructive operation against team tables.
    options = dict(host=os.environ["CLICKHOUSE_HOST"], port=int(os.getenv("CLICKHOUSE_PORT", "8123")),
                   username=os.getenv("CLICKHOUSE_USER", "default"),
                   password=os.getenv("CLICKHOUSE_PASSWORD", ""),
                   secure=os.getenv("CLICKHOUSE_SECURE", "").lower() in ("1", "true"))
    admin = clickhouse_connect.get_client(**options)
    name = "brain_integration_" + uuid.uuid4().hex
    admin.command(f"CREATE DATABASE {name}")
    client = clickhouse_connect.get_client(database=name, **options)
    monkeypatch.setenv("THREATS_TABLE", "incoming_threats")
    monkeypatch.setenv("EVENTS_TABLE", "events")
    monkeypatch.setenv("CLICKHOUSE_DATABASE", name)
    # Member 1's public interface opens its own short-lived connection.
    monkeypatch.setattr(threatfeed, "_client", lambda: clickhouse_connect.get_client(database=name, **options))
    try:
        ingest.ensure_schema(client)
        store.ensure_events_schema(client)
        yield client
    finally:
        client.close()
        admin.command(f"DROP DATABASE {name}")
        admin.close()


def seed(database, demo_server):
    rows = ingest.map_records([
        dict(id="demo-phish", url=f"{demo_server}/phish/", host="127.0.0.1",
             date_added="2026-10-09 18:01:00 UTC", threat="phishing"),
        dict(id="demo-benign", url=f"{demo_server}/benign/", host="127.0.0.1",
             date_added="2026-10-09 19:01:00 UTC", threat="phishing"),
        dict(id="demo-dead", url=f"{demo_server}/not-found", host="127.0.0.1",
             date_added="2026-10-09 19:02:00 UTC", threat="malware_download"),
    ], 3)
    rows = [(*row[:-1], "demo") for row in rows]  # planted pages are not an independent feed listing
    assert ingest.insert_rows(database, rows) == 3
    fresh, skipped = ingest.drop_duplicates(database, rows + rows[:1])
    assert fresh == [] and skipped == 4
    return rows


@needs_semgrep
def test_ingest_scan_writeback_and_graph_counts(database, demo_server, allow_private):
    rows = seed(database, demo_server)
    target = threatfeed.get_pending_targets(5)[0]
    assert target["domain"] == "127.0.0.1" and target["url_count"] == 3
    assert target["target_urls"] == [f"{demo_server}/not-found", f"{demo_server}/benign/", f"{demo_server}/phish/"]
    assert target["threat_types"] == ["malware_download", "phishing"]
    assert target["first_seen"].tzinfo == timezone.utc
    summary = worker.run_once(database)
    assert summary["by_status"] == {"VERIFIED": 1, "REJECTED": 1, "FETCH_FAILED": 1}
    result = dict(database.query("SELECT event_id, action_status FROM events FINAL").result_rows)
    assert result == {"demo-phish": "VERIFIED", "demo-benign": "REJECTED", "demo-dead": "FETCH_FAILED"}
    assert database.query("SELECT count() FROM incoming_threats WHERE takedown_status = 'SCANNED'").first_row[0] == 3
    assert threatfeed.get_pending_targets(5) == []
    assert worker.run_once(database)["total"] == 0
    assert database.query("SELECT count() FROM events").first_row[0] == 3
    stored = database.query("SELECT event_id, target_url, toUnixTimestamp(timestamp) FROM incoming_threats").result_rows
    assert {event_id: (url, seen) for event_id, url, seen in stored} == {
        row[0]: (row[1], int(row[4].timestamp())) for row in rows
    }
    data = telemetry.graph_data(database)
    assert [r["url_count"] for r in data["domain_activity"]] == [1, 2]
    assert {r["threat_type"]: r["event_count"] for r in data["threat_types"]} == {"phishing": 2, "malware_download": 1}
    assert {r["action_status"]: r["event_count"] for r in data["scanner_verdicts"]} == summary["by_status"]
    # Optional artifact output from this owned, synthetic end-to-end fixture.
    output = os.getenv("INTEGRATION_GRAPH_OUTPUT")
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.with_suffix(".json").write_text(json.dumps(data, indent=2), encoding="utf-8")
        telemetry.plot_graphs(data, path.with_suffix(".svg"), title="Synthetic integration test: 3 owned demo URLs")
        telemetry.plot_graphs(data, path.with_suffix(".png"), title="Synthetic integration test: 3 owned demo URLs")


def test_graphs_count_distinct_urls_and_current_verdict_versions(database, demo_server):
    assert telemetry.graph_data(database) == {"domain_activity": [], "threat_types": [], "scanner_verdicts": []}
    rows = seed(database, demo_server)
    database.insert("incoming_threats", [rows[0]], column_names=ingest.COLUMN_NAMES)
    event = dict(event_id="demo-phish", target_url=f"{demo_server}/phish/",
                 timestamp="2026-10-09T18:01:00Z", semgrep_detected=True,
                 confidence_score=0.95, evidence="fixture", action_status="VERIFIED", proof_url="")
    old = [event[key] for key in store.EVENT_COLUMNS]
    old[2] = datetime(2026, 10, 9, 18, 1, tzinfo=timezone.utc)
    old[6] = "REJECTED"
    database.insert("events", [old + [datetime(2020, 1, 1, tzinfo=timezone.utc)]],
                    column_names=list(store.EVENT_COLUMNS) + ["updated_at"])
    store.append_verdict(event, client=database)
    data = telemetry.graph_data(database)
    assert [r["url_count"] for r in data["domain_activity"]] == [1, 2]
    assert sum(r["event_count"] for r in data["threat_types"]) == 3
    assert data["scanner_verdicts"] == [{"action_status": "VERIFIED", "event_count": 1}]
    assert "demo-phish" not in {r["event_id"] for r in store.get_pending_events(client=database)}


def test_domain_url_limit_does_not_hide_pending_event_ids(database):
    records = [dict(id=f"many-{i}", url=f"http://many.example/{i}", host="many.example",
                    date_added=f"2026-10-09 18:{i:02d}:00 UTC", threat="phishing") for i in range(12)]
    ingest.insert_rows(database, ingest.map_records(records, 12))
    target = threatfeed.get_pending_targets(5)[0]
    assert target["url_count"] == 12
    assert len(target["target_urls"]) == 10
    assert len(store.get_pending_events(25, client=database)) == 12
    assert threatfeed.update_takedown_status("SCANNED", event_id="many-0", client=database) == 1
    assert threatfeed.get_pending_targets(5)[0]["url_count"] == 11


def test_status_failure_recovers_without_rescanning_a_persisted_verdict(database, demo_server, monkeypatch):
    seed(database, demo_server)
    calls = []

    def scanner(events, **kwargs):
        calls.append([event["event_id"] for event in events])
        return [({**event, "semgrep_detected": False, "confidence_score": 0.0,
                  "evidence": "failure-recovery fixture", "action_status": "REJECTED"}, []) for event in events]

    update = worker.update_takedown_status

    def fail(*args, **kwargs):
        raise RuntimeError("interrupted raw status write")

    monkeypatch.setattr(worker, "update_takedown_status", fail)
    with pytest.raises(RuntimeError, match="interrupted raw"):
        worker.run_once(database, scanner=scanner)
    assert database.query("SELECT count() FROM events FINAL").first_row[0] == 1
    monkeypatch.setattr(worker, "update_takedown_status", update)
    assert worker.run_once(database, scanner=scanner)["total"] == 2
    assert len(calls[0]) == 3 and len(calls[1]) == 2
    assert calls[0][0] not in calls[1]
    assert threatfeed.get_pending_targets(5) == []
