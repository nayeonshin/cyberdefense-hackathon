"""Failure cases discovered during the full Member 4 QA audit."""
from pathlib import Path

import pytest
import yaml

from shipper.model import current_confirmation, now_iso, public_proof
from shipper.settings import Settings
from shipper.storage import write_json
from tests.test_presentation import app_fixture


@pytest.mark.parametrize("url", [
    "http://localhost./receipt", "http://127.0.0.1./receipt",
    "http://host.internal./receipt", "http://127%2e0%2e0%2e1/",
    "http://127。0。0。1/", "http://0177.0.0.1/", "http://0x7f.0.0.1/",
    "http://host.invalid../receipt",
])
def test_browser_normalized_private_proofs_are_rejected(url):
    assert public_proof(url) is None


def test_renderer_keeps_combined_team_entrypoint(tmp_path, monkeypatch):
    from shipper.render_deploy import render
    template = Path(__file__).parents[1] / "deploy.yaml"
    (tmp_path / "deploy.yaml").write_bytes(template.read_bytes())
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DATA_SOURCE", "files")
    monkeypatch.setenv("RUN_MODE", "controlled")
    command = '["python","-m","shipper.team_pipeline"]'
    monkeypatch.setenv("TEAM_PIPELINE_COMMAND_JSON", command)
    monkeypatch.setenv("LIVE_EMAIL", "1")
    render("ghcr.io/nayeonshin/cyberdefense-hackathon:" + "a" * 40, "deploy.private.yaml")
    manifest = yaml.safe_load((tmp_path / "deploy.private.yaml").read_text())
    env = dict(x.split("=", 1) for x in manifest["services"]["orchestrator"]["env"])
    assert env["TEAM_PIPELINE_COMMAND_JSON"] == command
    assert env["LIVE_EMAIL"] == "0"


@pytest.mark.parametrize("name,content", [
    ("heartbeat.json", '{"updated_at":"not-a-date","status":"running"}'),
    ("supervisor.json", '{"status":'),
    ("pipeline.json", '[]'),
    ("target-check.json", '{"checked_at":"not-a-date","http_status":410}'),
])
def test_corrupt_runtime_metadata_preserves_dashboard(tmp_path, monkeypatch, name, content):
    app, _ = app_fixture(tmp_path, monkeypatch)
    app.run()
    settings = Settings.from_env()
    settings.run_dir.mkdir(parents=True, exist_ok=True)
    (settings.run_dir / name).write_text(content)
    app.run()
    assert not app.exception
    assert any(name in item.value and "unavailable" in item.value for item in app.error)
    assert len(app.dataframe[0].value) == 4


def test_malformed_confirmation_is_not_current():
    assert not current_confirmation({"checked_at": "invalid"}, {"started_at": now_iso()})


def test_future_heartbeat_is_stale(tmp_path, monkeypatch):
    app, _ = app_fixture(tmp_path, monkeypatch)
    write_json(Settings.from_env().run_dir / "heartbeat.json", {
        "status": "running", "updated_at": "2099-01-01T00:00:00Z", "started_at": now_iso(),
    })
    app.run()
    assert not app.exception
    assert any("stale" in item.value for item in app.warning)


def test_future_ingestion_does_not_inflate_current_throughput(tmp_path):
    from shipper.data import calculate_metrics
    from tests.test_shipper import config, record
    recent, future = record(config(tmp_path)), record(config(tmp_path))
    future["metadata"]["ingested_at"] = "2099-01-01T00:00:00Z"
    metrics = calculate_metrics([recent, future], [])
    assert metrics["total_events"] == 2
    assert metrics["ingested_per_minute"] == 1


def test_acceptance_waits_for_worker_recovery(tmp_path):
    import json
    from actor.contract import Receipt
    from shipper.verify_run import inspect_run
    from tests.test_shipper import config, record
    settings = config(tmp_path)
    item = record(settings)  # Supplied unit-test data, not sponsor scan evidence.
    event = item["event"]
    write_json(settings.run_dir / "events.json", [item])
    write_json(settings.run_dir / "scan-findings.json", {"event_id": event["event_id"], "findings": ["supplied test finding"]})
    rows = [Receipt(event["event_id"], event["target_url"], "localhost", action, 2, "test", status,
                    dry_run=False).to_dict() for action, status in [("mock_registrar", "SENT"), ("confirm", "CONFIRMED_DOWN")]]
    (settings.run_dir / "actions.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    start = now_iso()
    write_json(settings.run_dir / "target-check.json", {"checked_at": now_iso(), "started_at": start, "http_status": 410})
    heartbeat = {"started_at": start, "status": "degraded"}
    write_json(settings.run_dir / "heartbeat.json", heartbeat)
    assert inspect_run(settings) is None
    heartbeat["status"] = "running"
    write_json(settings.run_dir / "heartbeat.json", heartbeat)
    assert inspect_run(settings)["submitted_receipts"] == 1


def test_acceptance_wait_retries_connections_without_leaking_messages(tmp_path, monkeypatch, capsys):
    from unittest.mock import Mock
    from clickhouse_connect.driver.exceptions import OperationalError
    from shipper import verify_run
    from tests.test_shipper import config
    inspect = Mock(side_effect=[OperationalError("private connection detail"), {"within_recording_window": True}])
    monkeypatch.setattr(verify_run, "inspect_run", inspect)
    monkeypatch.setattr(verify_run.Settings, "from_env", lambda: config(tmp_path))
    monkeypatch.setattr(verify_run.time, "sleep", lambda _: None)
    monkeypatch.setattr("sys.argv", ["verify_run", "--wait", "1"])
    verify_run.main()
    assert inspect.call_count == 2
    output = capsys.readouterr().out
    assert "Waiting for dependency recovery" in output
    assert "private connection detail" not in output


def test_crash_after_receipt_before_recheck_state_recovers(tmp_path, monkeypatch):
    from shipper.controlled import start_registrar
    from shipper.data import FileSource
    from shipper.worker import Coordinator, DurableLedger, LIVE_FLAGS
    from tests.test_shipper import config, record
    settings = config(tmp_path)
    for flag in LIVE_FLAGS:
        monkeypatch.setenv(flag, "0")
    monkeypatch.setenv("ACTOR_STOP", "0")
    monkeypatch.setenv("MOCK_REGISTRAR_URL", "http://localhost:8099")
    monkeypatch.setenv("OUTBOX_DIR", str(settings.run_dir / "outbox"))
    write_json(settings.run_dir / "events.json", [record(settings)])
    source = FileSource(settings)
    ledger = DurableLedger(settings.run_dir)
    server = start_registrar(settings.run_dir)
    try:
        monkeypatch.setattr(ledger, "save_state", lambda _: (_ for _ in ()).throw(OSError("simulated interrupted write")))
        with pytest.raises(OSError):
            Coordinator(settings, source, ledger).tick()
        restarted = Coordinator(settings, source)
        restarted.tick()
        restarted.last_recheck = 0
        restarted.tick()
        rows = source.get_receipts()
        assert len(server.tickets) == 1
        assert sum(r["status"] == "SENT" for r in rows) == 1
        assert sum(r["status"] == "CONFIRMED_DOWN" for r in rows) == 1
    finally:
        server.shutdown()
        server.server_close()
