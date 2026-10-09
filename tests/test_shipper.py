import json
import time
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests
from shipper.controlled import start_registrar
from shipper.data import ClickHouseSource, FixtureSource, FileSource, identifier
from shipper.model import FIELDS, now_iso, public_proof, scan_label, validate_event
from shipper.settings import Settings
from shipper.storage import read_json, write_json
from shipper.worker import Coordinator, DurableLedger, LIVE_FLAGS


def config(tmp_path, source="files", mode="controlled"):
    return Settings(source, mode, "test-run", tmp_path, "http://localhost:8099/site", 1, 1)


def record(settings):
    # Test-provided evidence only. This test does NOT demonstrate real Semgrep usage.
    event = {"event_id": "test-1", "target_url": settings.controlled_url, "timestamp": now_iso(),
             "semgrep_detected": True, "confidence_score": 0.96, "evidence": "TEST PROVIDED EVIDENCE",
             "action_status": "PENDING", "proof_url": ""}
    return {"event": event, "metadata": {"ingested_at": now_iso(), "scan_completed_at": now_iso(),
             "scanner": "semgrep", "run_id": settings.run_id}}


def test_contract_rejects_truthy_strings_and_extra_fields(tmp_path):
    event = record(config(tmp_path))["event"]
    assert tuple(validate_event(event)) == FIELDS
    for change in ({"semgrep_detected": "false"}, {"confidence_score": float("nan")}, {"extra": True}):
        with pytest.raises(ValueError):
            validate_event({**event, **change})


@pytest.mark.parametrize("url", ["file:///secret", "javascript:alert(1)", "http://localhost:8099/tickets/1",
    "http://127.0.0.1/", "http://169.254.169.254/", "http://10.0.0.1/", "https://user:password@example.com",
    "http://2130706433/", "http://0x7f000001/", "https://example.com\n", "https://foo.invalid/"])
def test_private_and_unsafe_proofs_not_clickable(url):
    assert public_proof(url) is None


def test_public_https_proof():
    assert public_proof("https://github.com/team/feed/issues/1")


def test_pending_is_not_a_negative_scan(tmp_path):
    item = record(config(tmp_path))
    item["event"]["semgrep_detected"] = False
    assert scan_label(item["event"], {}) == "Pending scan"
    assert scan_label(item["event"], item["metadata"]) == "No rule matched"


def test_fixtures_never_claim_submitted_actions(tmp_path):
    source = FixtureSource(config(tmp_path, "fixtures", "preview"))
    assert source.simulated
    assert source.get_metrics()["submitted_actions"] == 0


def test_clickhouse_errors_propagate_without_fixture_fallback(tmp_path):
    client = Mock()
    client.query.side_effect = ConnectionError("connection unavailable")
    source = ClickHouseSource(config(tmp_path, "clickhouse"), client)
    with pytest.raises(ConnectionError):
        source.get_events()
    with pytest.raises(ValueError):
        identifier("incoming_threats; DROP TABLE actions")


def test_worker_bootstraps_actions_before_reading_events(tmp_path):
    settings = config(tmp_path, "clickhouse")
    order = []
    source = Mock()
    source.get_events.side_effect = lambda: order.append("events") or []
    ledger = Mock()
    ledger.flush.side_effect = lambda _: order.append("bootstrap")
    coordinator = Coordinator(settings, source, ledger)
    coordinator.last_recheck = time.monotonic()
    coordinator.tick()
    assert order[:2] == ["bootstrap", "events"]


def test_preview_never_dispatches(tmp_path, monkeypatch):
    settings = config(tmp_path, "fixtures", "preview")
    dispatch = Mock()
    monkeypatch.setattr("shipper.worker.dispatch", dispatch)
    Coordinator(settings, FixtureSource(settings)).tick()
    dispatch.assert_not_called()


def test_controlled_dispatch_restart_persistence_and_negative_gate(tmp_path, monkeypatch):
    settings = config(tmp_path)
    settings.run_dir.mkdir(parents=True)
    for key in LIVE_FLAGS:
        monkeypatch.setenv(key, "0")
    monkeypatch.setenv("MOCK_REGISTRAR_URL", "http://localhost:8099")
    monkeypatch.setenv("OUTBOX_DIR", str(settings.run_dir / "outbox"))
    monkeypatch.setenv("ACTOR_STOP", "0")
    item = record(settings)
    write_json(settings.run_dir / "events.json", [item])
    source = FileSource(settings)
    server = start_registrar(settings.run_dir)
    try:
        coordinator = Coordinator(settings, source)
        coordinator.tick()
        coordinator.last_recheck = 0
        coordinator.tick()
        rows = source.get_receipts()
        assert sum(r["action"] == "mock_registrar" and r["status"] == "SENT" for r in rows) == 1
        assert any(r["status"] == "CONFIRMED_DOWN" for r in rows)
        assert requests.head(settings.controlled_url, timeout=2).status_code == 410
        ticket_count = len(server.tickets)
        # Restart coordinator with the same run and ledger: no repeat action.
        Coordinator(settings, source).tick()
        assert len(server.tickets) == ticket_count
        assert len(source.get_receipts()) == len(rows)
        assert read_json(settings.run_dir / "target-check.json")["suspended"]
    finally:
        server.shutdown()
        server.server_close()
    server = start_registrar(settings.run_dir)
    try:
        assert server.suspended and len(server.tickets) == 1
        assert requests.head(settings.controlled_url, timeout=2).status_code == 410
        # Simulate lost response: repeated report returns the same ticket.
        existing = next(iter(server.tickets.values()))
        response = requests.post("http://localhost:8099/abuse", json={k: existing[k] for k in ("event_id", "url", "evidence_sha256")}, timeout=2)
        assert response.json()["ticket"] == existing["ticket"]
        assert len(server.tickets) == 1
    finally:
        server.shutdown()
        server.server_close()


def test_uncompleted_or_unproven_scan_cannot_dispatch(tmp_path, monkeypatch):
    settings = config(tmp_path)
    source = Mock(spec=FileSource)
    item = record(settings)
    item["metadata"]["scanner"] = "fixture"
    source.get_events.return_value = [item]
    fake_dispatch = Mock()
    monkeypatch.setattr("shipper.worker.dispatch", fake_dispatch)
    coordinator = Coordinator(settings, source)
    coordinator.last_recheck = time.monotonic()
    coordinator.tick()
    fake_dispatch.assert_not_called()


def test_clickhouse_receipt_replay_retries_once(tmp_path):
    from actor.contract import Receipt
    ledger = DurableLedger(tmp_path)
    ledger.append(Receipt("test-1", "http://localhost:8099/site", "localhost", "mock_registrar", 2,
                          "mock-registrar", "SENT", dry_run=False))
    client = Mock()
    client.query.return_value.first_row = (0,)
    client.insert.side_effect = [ConnectionError(), None]
    with pytest.raises(ConnectionError):
        ledger.flush(client)
    assert not ledger.synced_path.exists()
    ledger.flush(client)
    ledger.flush(client)
    assert client.insert.call_count == 2


def test_dashboard_reruns_are_read_only(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    monkeypatch.setenv("DATA_SOURCE", "fixtures")
    monkeypatch.setenv("RUN_MODE", "preview")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    fake_dispatch = Mock()
    monkeypatch.setattr("actor.dispatch.dispatch", fake_dispatch)
    app = AppTest.from_file(str(Path(__file__).parent.parent / "dashboard.py"), default_timeout=20).run()
    assert not app.exception
    assert any("Simulated data" in item.value for item in app.warning)
    app.selectbox[0].select("demo-102").run()
    assert not app.exception
    app.run()
    assert not app.exception
    fake_dispatch.assert_not_called()
