"""Opt-in integration against a disposable database, with the real Semgrep worker."""
import os

import pytest

from actor.contract import Receipt
from actor.ledger import COLUMNS, DDL_TEMPLATE, _parse
from brain import worker
from shipper.backend_source import BackendSource
from shipper.model import FIELDS, scan_label
from shipper.settings import Settings
from tests.test_clickhouse_roundtrip import database, seed  # noqa: F401
from tests.test_brain import demo_server, allow_private, needs_semgrep  # noqa: F401

pytestmark = pytest.mark.skipif(os.getenv("RUN_CLICKHOUSE_TESTS") != "1", reason="isolated ClickHouse required")


@needs_semgrep
def test_native_backend_tables_render_real_scan_and_receipts(database, demo_server, allow_private, tmp_path, monkeypatch):
    monkeypatch.setenv("ACTIONS_TABLE", "integration_actions")
    settings = Settings("backend", "preview", "integration", tmp_path, "http://localhost:8099/site", 2, 5)
    source = BackendSource(settings, database)
    seed(database, demo_server)
    assert source.get_metrics()["pending_scans"] == 3
    assert source.get_receipts() == []  # Actor has not bootstrapped its table yet.
    worker.run_once(database)
    rows = {r["event"]["event_id"]: r for r in source.get_events()}
    assert all(set(r["event"]) == set(FIELDS) for r in rows.values())
    assert scan_label(rows["demo-benign"]["event"], rows["demo-benign"]["metadata"]) == "No rule matched"
    assert scan_label(rows["demo-dead"]["event"], rows["demo-dead"]["metadata"]) == "Scan failed"
    assert rows["demo-phish"]["event"]["semgrep_detected"]
    assert rows["demo-phish"]["metadata"]["scan_completed_at"]
    metrics = source.get_metrics()
    assert metrics["total_events"] == 3 and metrics["detected"] == 1 and metrics["pending_scans"] == 1

    # A saved test message must be visible but never count as a submitted action.
    database.command(DDL_TEMPLATE.format(table="integration_actions"))
    receipt = Receipt("demo-phish", rows["demo-phish"]["event"]["target_url"], "localhost",
                      "notify_host", 1, "test.invalid", "SINK", dry_run=False, detail="integration test fixture").to_dict()
    values = [receipt[k] for k in COLUMNS]; values[-1] = _parse(receipt["created_at"])
    database.insert("integration_actions", [values], column_names=COLUMNS)
    assert source.get_receipts("demo-phish")[0]["status"] == "SINK"
    assert source.get_metrics()["submitted_actions"] == 0

    # Emulate the Actor's current-version write: its time is not a scan time.
    database.command("ALTER TABLE events UPDATE action_status='TAKEN_DOWN' WHERE event_id='demo-phish'",
                     settings={"mutations_sync": 1})
    changed = next(r for r in source.get_events() if r["event"]["event_id"] == "demo-phish")
    assert changed["metadata"]["scan_completed"] and changed["metadata"]["scan_completed_at"] is None
    assert source.get_metrics()["detected"] == 1
