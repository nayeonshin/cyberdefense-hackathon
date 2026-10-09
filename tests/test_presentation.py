from unittest.mock import Mock

from streamlit.testing.v1 import AppTest

from shipper.presentation import accept_queue_selection, resolve_selection, timeline, timeline_html
from shipper.data import FixtureSource
from shipper.settings import Settings
from shipper.storage import write_json


def test_selection_keeps_event_when_rows_arrive_and_reorder():
    state = {"queue_event_ids": ["a", "b"], "threat_queue": {"selection": {"rows": [1]}}}
    accept_queue_selection(state)
    assert state["selected_event"] == "b"
    assert resolve_selection(["new", "b", "a"], state["selected_event"]) == ("b", False)
    assert resolve_selection(["new", "a"], "b") == ("new", True)
    assert resolve_selection([], "b") == (None, True)
    assert resolve_selection(["a", "b"], requested="b") == ("b", False)
    assert resolve_selection(["a", "b"], requested="missing") == ("a", False)


def sample():
    return {"event": {"event_id": "x", "semgrep_detected": True, "action_status": "PENDING"},
            "metadata": {"ingested_at": "2026-10-09T19:00:00Z", "scan_completed_at": "2026-10-09T19:00:01Z"}}


def receipt(status, dry_run=False):
    return {"event_id": "x", "status": status, "dry_run": dry_run, "created_at": "2026-10-09T19:00:03Z"}


def test_timeline_requires_actual_evidence_and_preserves_negative_failure_states():
    record = sample()
    assert timeline(record, [receipt("SENT", True)])[2]["detail"] == "Awaiting receipt"
    assert timeline(record, [receipt("SINK")])[2]["detail"] == "Saved test message"
    assert timeline(record, [receipt("SKIPPED")])[2]["detail"] == "Skipped"
    assert timeline(record, [receipt("FAILED")])[2]["tone"] == "danger"
    record["metadata"]["scan_completed_at"] = None
    assert timeline(record, [])[1]["detail"] == "Pending scan"
    record["event"]["action_status"] = "SCAN_FAILED"
    assert timeline(record, [])[1]["detail"] == "Scan failed"
    record = sample()
    record["event"]["semgrep_detected"] = False
    stages = timeline(record, [])
    assert stages[1]["detail"] == "No rule matched"
    assert stages[2]["detail"] == stages[3]["detail"] == "Not applicable"
    stages = timeline(sample(), [receipt("SENT"), receipt("CONFIRMED_DOWN")], historical=True)
    assert stages[2]["detail"] == "19:00:03 UTC"
    assert stages[3]["detail"] == "Historical confirmation"
    assert timeline(sample(), [receipt("SENT"), receipt("CONFIRMED_DOWN")])[3]["detail"] == "19:00:03 UTC"


def test_timeline_escapes_strings():
    assert "<script>" not in timeline_html([{"title": "<script>alert(1)</script>", "detail": "<img>", "tone": "neutral"}])


def app_fixture(tmp_path, monkeypatch):
    from pathlib import Path
    monkeypatch.setenv("DATA_SOURCE", "fixtures")
    monkeypatch.setenv("RUN_MODE", "preview")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    source = FixtureSource(Settings.from_env())
    monkeypatch.setattr("shipper.data.make_source", lambda _: source)
    return AppTest.from_file(str(Path(__file__).parent.parent / "dashboard.py"), default_timeout=30), source


def test_app_deep_link_reordering_removal_and_escaped_evidence(tmp_path, monkeypatch):
    app, source = app_fixture(tmp_path, monkeypatch)
    app.query_params["event"] = "demo-102"
    app.run()
    assert not app.exception
    assert app.session_state["selected_event"] == "demo-102"
    source.fixture["records"].reverse()
    app.run()
    assert app.session_state["selected_event"] == "demo-102"
    assert app.session_state["threat_queue"]["selection"]["rows"] == [1]
    source.fixture["records"] = [r for r in source.fixture["records"] if r["event"]["event_id"] != "demo-102"]
    source.fixture["records"][0]["event"]["evidence"] = '<script>alert("unsafe")</script>'
    app.run()
    assert not app.exception
    assert any("no longer available" in x.value for x in app.info)
    assert any('<script>alert("unsafe")</script>' in x.value for x in app.code)
    assert all("<script>" not in str(x.proto) for x in app.get("html"))


def test_app_stale_snapshot_worker_failure_and_empty_state(tmp_path, monkeypatch):
    app, source = app_fixture(tmp_path, monkeypatch)
    app.run()
    assert not app.exception
    assert any("stale" in x.value for x in app.warning)
    write_json(Settings.from_env().run_dir / "supervisor.json", {"status": "failed", "process": "worker"})
    source.get_events = Mock(side_effect=ConnectionError())
    app.run()
    assert not app.exception
    assert any("last successful snapshot" in x.value for x in app.error)
    assert any("process exited: worker" in x.value for x in app.error)
    assert len(app.dataframe[0].value) == 4
    source.get_events = lambda: []
    source.get_metrics = lambda: dict(ingested_per_minute=0, total_events=0, pending_scans=0, detected=0, submitted_actions=0)
    app.run()
    assert not app.exception
    assert any("No events" in x.value for x in app.info)


def test_app_invalid_proof_uses_saved_receipt(tmp_path, monkeypatch):
    app, source = app_fixture(tmp_path, monkeypatch)
    source.fixture["receipts"][0]["proof_url"] = "javascript:alert(1)"
    app.run()
    assert not app.exception
    assert all("javascript:" not in str(x.proto) for x in app.get("link_button"))
