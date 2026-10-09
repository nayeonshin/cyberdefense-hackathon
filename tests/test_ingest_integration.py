from datetime import datetime, timezone
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import ingest
import threatfeed
from brain import clickhouse as store
from brain import worker


@pytest.fixture(autouse=True)
def isolate_scan_contract_tests(monkeypatch):
    # Reconciliation is exercised against a real database in the roundtrip suite.
    monkeypatch.setattr(worker, "reconcile_completed", lambda *a, **k: None)


def record(event_id="feed-1", **changes):
    return dict(id=event_id, url="https://demo.example/login", host="demo.example:443",
                date_added="2026-10-09 18:55:15 UTC", threat="phishing", **changes)


def test_mapping_handles_malformed_filtered_records_and_preserves_utc():
    rows = ingest.map_records([None, 3, "bad", record()], 5, threat_type="phishing")
    assert len(rows) == 1
    assert dict(zip(ingest.COLUMN_NAMES, rows[0])) == {
        "event_id": "feed-1", "target_url": "https://demo.example/login",
        "domain": "demo.example", "ip_address": "",
        "timestamp": datetime(2026, 10, 9, 18, 55, 15, tzinfo=timezone.utc),
        "threat_type": "phishing", "takedown_status": "PENDING", "feed_source": "urlhaus",
    }
    for limit in (0, -1, True):
        with pytest.raises(ValueError):
            ingest.map_records([], limit)


def test_dedup_handles_duplicates_within_the_same_feed_response():
    rows = ingest.map_records([record("old"), record("new"), record("new")], 3)
    client = SimpleNamespace(query=lambda *a, **k: SimpleNamespace(result_rows=[("old",)]))
    fresh, skipped = ingest.drop_duplicates(client, rows)
    assert [row[0] for row in fresh] == ["new"]
    assert skipped == 2


def test_empty_database_and_utc_handoff_do_not_close_borrowed_client():
    calls = []
    db = SimpleNamespace(command=lambda *a, **k: calls.append(a),
                         query=lambda *a, **k: SimpleNamespace(result_rows=[]))
    assert store.get_pending_events(client=db) == []
    db.query = lambda *a, **k: SimpleNamespace(result_rows=[
        ("id-1", "https://demo.example/full/path", datetime(2026, 10, 9), "urlhaus")])
    event = store.get_pending_events(client=db)[0]
    assert event["timestamp"] == "2026-10-09T00:00:00Z"
    assert event["target_url"] == "https://demo.example/full/path"
    assert event["listed_on_feed"] is True


def pending():
    return dict(event_id="feed-1", target_url="https://demo.example/login",
                timestamp="2026-10-09T18:55:15Z", semgrep_detected=None,
                confidence_score=None, evidence="", action_status="PENDING",
                proof_url="", listed_on_feed=True)


def verdict(event):
    return {**event, "semgrep_detected": True, "confidence_score": 0.75,
            "evidence": "Semgrep matched a credential request", "action_status": "VERIFIED"}


def test_worker_preserves_contract_and_uses_feed_flag_without_persisting_extras(monkeypatch):
    monkeypatch.setattr(worker, "get_pending_events", lambda *a, **k: [pending()])
    inserts = []
    db = SimpleNamespace(command=lambda *a, **k: None,
                         insert=lambda *a, **k: inserts.append((a, k)))

    def scanner(events, listed_on_feed):
        assert listed_on_feed == [True]
        assert "listed_on_feed" not in events[0]
        return [({**verdict(events[0]), "findings": ["not part of the row"]}, [])]

    monkeypatch.setattr(worker, "update_takedown_status", lambda *a, **k: 1)
    assert worker.run_once(db, scanner=scanner)["by_status"] == {"VERIFIED": 1}
    args, kwargs = inserts[0]
    assert args[0] == "events"
    assert kwargs["column_names"] == list(store.EVENT_COLUMNS)
    assert len(args[1][0]) == 8
    assert args[1][0][0:2] == ["feed-1", "https://demo.example/login"]


@pytest.mark.parametrize("failure", ["exception", "missing", "identity", "mutated-input", "invalid-score"])
def test_failed_or_malformed_scan_never_writes_a_verdict(monkeypatch, failure):
    monkeypatch.setattr(worker, "get_pending_events", lambda *a, **k: [pending()])
    writes = []
    monkeypatch.setattr(worker, "append_verdict", lambda *a, **k: writes.append(a))

    def scanner(events, listed_on_feed):
        if failure == "exception":
            raise RuntimeError("scanner unavailable")
        if failure == "missing":
            return []
        if failure == "mutated-input":
            events[0]["target_url"] = "https://different.example/"
        result = verdict(events[0])
        if failure == "identity":
            result["event_id"] = "wrong-event"
        if failure == "invalid-score":
            result["confidence_score"] = float("nan")
        return [(result, [])]

    with pytest.raises((RuntimeError, ValueError)):
        worker.run_once(object(), scanner=scanner)
    assert writes == []


def test_partial_write_failure_stops_before_later_events(monkeypatch):
    events = [{**pending(), "event_id": str(i)} for i in range(3)]
    monkeypatch.setattr(worker, "get_pending_events", lambda *a, **k: events)
    writes = []

    def append(event, **kwargs):
        if event["event_id"] == "1":
            raise RuntimeError("write failed")
        writes.append(event["event_id"])

    monkeypatch.setattr(worker, "append_verdict", append)
    monkeypatch.setattr(worker, "update_takedown_status", lambda *a, **k: 1)
    with pytest.raises(RuntimeError, match="write failed"):
        worker.run_once(object(), scanner=lambda events, **k: [(verdict(e), []) for e in events])
    assert writes == ["0"]


def test_legacy_status_update_uses_parameters_and_synchronous_mutation():
    calls = []
    db = SimpleNamespace(query=lambda *a, **k: SimpleNamespace(first_row=[1]),
                         command=lambda *a, **k: calls.append((a, k)))
    assert threatfeed.update_takedown_status("SCANNED", event_id="id'quoted", client=db) == 1
    assert "id'quoted" not in calls[0][0][0]
    assert calls[0][1]["parameters"]["selector"] == "id'quoted"
    assert calls[0][1]["settings"] == {"mutations_sync": 1}
    for args in ({}, {"domain": "x", "event_id": "y"}):
        with pytest.raises(ValueError):
            threatfeed.update_takedown_status("SCANNED", client=db, **args)


def test_smoke_import_does_not_switch_database_table_or_working_directory(monkeypatch):
    monkeypatch.setenv("THREATS_TABLE", "production_marker")
    previous = Path.cwd()
    spec = importlib.util.spec_from_file_location("smoke_import_check", Path(__file__).with_name("smoke_test.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert os.environ["THREATS_TABLE"] == "production_marker"
    assert Path.cwd() == previous
    assert module.TEST_TABLE.startswith("incoming_threats_test_")
