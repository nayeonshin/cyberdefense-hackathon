from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from streamlit.testing.v1 import AppTest

from shipper.backend_source import BackendSource
from shipper.model import FIELDS, scan_label
from shipper.motion_model import motion_state
from shipper.settings import Settings

STAMP = datetime(2026, 10, 9, 19, tzinfo=timezone.utc)


class ReadOnlyDB:
    def __init__(self, status="VERIFIED", detected=True, tables=True):
        self.status, self.detected, self.tables = status, detected, tables
        self.calls = []
        self.target = "https://owned.example.invalid"

    def query(self, sql, parameters=None):
        assert sql.startswith(("SELECT", "EXISTS")), sql
        self.calls.append((sql, parameters))
        if sql.startswith("EXISTS"):
            return SimpleNamespace(first_row=[int(self.tables)])
        if " AS total_events" in sql:
            rows = [dict(total_events=501, ingested_per_minute=3, pending_scans=4, detected=12)]
        elif " AS submitted_actions" in sql:
            rows = [dict(submitted_actions=1)]
        elif "FROM events FINAL" in sql:
            rows = [dict(event_id="evt", target_url=self.target, action_status=self.status,
                         semgrep_detected=self.detected, confidence_score=.6, updated_at=STAMP,
                         evidence='<form action="https://example.invalid/collect">', proof_url="javascript:alert(1)")]
        elif "SELECT * FROM actions" in sql:
            rows = []
        else:
            rows = [dict(event_id="evt", target_url="https://owned.example.invalid",
                         event_time=STAMP, ingested_at=STAMP)]
        return SimpleNamespace(named_results=lambda: rows)

    def close(self):
        pass


def runtime(tmp_path):
    return Settings("backend", "preview", "read-only", tmp_path, "http://localhost:8099/site", 2, 5)


@pytest.mark.parametrize("status,detected,label", [
    ("VERIFIED", True, "Threat detected"), ("REJECTED", False, "No rule matched"),
    ("PENDING", None, "Pending scan"), ("FETCH_FAILED", False, "Scan failed"),
    ("PUBLISHED_TAKEDOWN", True, "Threat detected"), ("TAKEN_DOWN", True, "Threat detected")])
def test_backend_projection_preserves_statuses_and_exact_contract(tmp_path, monkeypatch, status, detected, label):
    for name in ("THREATS_TABLE", "VERDICTS_TABLE", "ACTIONS_TABLE"):
        monkeypatch.delenv(name, raising=False)
    source = BackendSource(runtime(tmp_path), ReadOnlyDB(status, detected))
    row = source.get_events()[0]
    assert set(row["event"]) == set(FIELDS)
    assert scan_label(row["event"], row["metadata"]) == label
    if status in {"PUBLISHED_TAKEDOWN", "TAKEN_DOWN"}:
        assert row["metadata"]["scan_completed"]
        assert row["metadata"]["scan_completed_at"] is None
        state = motion_state(row, [], historical=True)
        assert state["status"] == "Threat detected" and not state["replay"]
        assert state["stages"][1]["reached"] and state["stages"][1]["recorded"] is None


def test_fresh_backend_schema_does_not_create_tables_or_hide_pending(tmp_path):
    source = BackendSource(runtime(tmp_path), ReadOnlyDB(tables=False))
    row = source.get_events()[0]
    assert scan_label(row["event"], row["metadata"]) == "Pending scan"
    assert source.get_receipts() == []
    assert source.get_metrics()["submitted_actions"] == 0


def test_receipt_parameters_scope_and_metrics_are_not_limited_to_visible_rows(tmp_path):
    db = ReadOnlyDB()
    source = BackendSource(runtime(tmp_path), db)
    source.get_receipts("untrusted' OR 1=1")
    sql, params = db.calls[-1]
    assert "untrusted" not in sql and params["event"] == "untrusted' OR 1=1"
    assert "(event_id, target_url)" in sql
    metrics = source.get_metrics()
    assert metrics["total_events"] == 501 and metrics["submitted_actions"] == 1
    assert "LIMIT" not in next(sql for sql, _ in db.calls if " AS total_events" in sql)


def test_wrong_target_verdict_never_attaches_to_event(tmp_path):
    db = ReadOnlyDB(); db.target = "https://different.invalid"
    row = BackendSource(runtime(tmp_path), db).get_events()[0]
    assert scan_label(row["event"], row["metadata"]) == "Pending scan"


def test_backend_mode_refuses_dispatch_and_unsafe_table_names(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_SOURCE", "backend")
    monkeypatch.setenv("RUN_MODE", "controlled")
    with pytest.raises(ValueError, match="read-only"):
        Settings.from_env()
    monkeypatch.setenv("THREATS_TABLE", "raw; DROP TABLE events")
    with pytest.raises(ValueError, match="identifiers"):
        BackendSource(runtime(tmp_path), ReadOnlyDB())


def test_backend_dashboard_is_read_only_and_escapes_evidence(tmp_path, monkeypatch):
    from pathlib import Path
    monkeypatch.setenv("DATA_SOURCE", "backend")
    monkeypatch.setenv("RUN_MODE", "preview")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    source = BackendSource(runtime(tmp_path), ReadOnlyDB("TAKEN_DOWN"))
    monkeypatch.setattr("shipper.data.make_source", lambda _: source)
    app = AppTest.from_file(str(Path(__file__).parents[1] / "dashboard.py"), default_timeout=30)
    app.run(); app.run()
    assert not app.exception
    assert any("Connected backend" in x.value for x in app.info)
    assert any("not exposed" in x.value for x in app.warning)
    assert any("<form" in x.value for x in app.code)
    assert all("javascript:" not in str(x.proto) for x in app.get("link_button"))
    assert not (tmp_path / "coordinator.lock").exists()


def test_failed_source_switch_does_not_relabel_fixtures_as_backend_data(tmp_path, monkeypatch):
    from tests.test_presentation import app_fixture
    app, source = app_fixture(tmp_path, monkeypatch)
    app.run()
    assert app.session_state["snapshot"]["events"]
    monkeypatch.setenv("DATA_SOURCE", "backend")
    source.get_events = lambda: (_ for _ in ()).throw(ConnectionError())
    app.run()
    assert not app.exception
    assert app.session_state.get("snapshot") is None
    assert any("Waiting for data" in item.value for item in app.info)
