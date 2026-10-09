import pytest
import requests

from shipper.controlled import start_registrar
from shipper.data import FileSource
from shipper.model import FIELDS, scan_label
from shipper.settings import Settings
from shipper.storage import read_json
from shipper.team_pipeline import TeamPipeline
from shipper.worker import Coordinator, LIVE_FLAGS


def settings(tmp_path):
    return Settings("files", "controlled", "real-semgrep-test", tmp_path,
                    "http://localhost:8099/site", 1, 1)


def test_actual_team_scan_reaches_confirmed_suspension(tmp_path, monkeypatch):
    runtime = settings(tmp_path)
    for key in LIVE_FLAGS:
        monkeypatch.setenv(key, "0")
    monkeypatch.setenv("MOCK_REGISTRAR_URL", "http://localhost:8099")
    monkeypatch.setenv("OUTBOX_DIR", str(runtime.run_dir / "outbox"))
    monkeypatch.setenv("ACTOR_STOP", "0")
    server = start_registrar(runtime.run_dir)
    try:
        pipeline = TeamPipeline(runtime)
        pipeline.tick()
        pending = read_json(pipeline.path)[0]
        assert set(pending["event"]) == set(FIELDS)
        assert scan_label(pending["event"], pending["metadata"]) == "Pending scan"
        pipeline.tick()  # Executes Member 2's actual Semgrep CLI, not a mock.
        scanned = read_json(pipeline.path)[0]
        assert scanned["metadata"]["scanner"] == "semgrep"
        assert scanned["metadata"]["scan_completed_at"]
        assert "fake-login-form" in scanned["event"]["evidence"]
        assert scanned["event"]["semgrep_detected"] is True
        assert read_json(runtime.run_dir / "scan-findings.json")["findings"]
        source = FileSource(runtime)
        coordinator = Coordinator(runtime, source)
        coordinator.tick()
        coordinator.last_recheck = 0
        coordinator.tick()
        assert requests.head(runtime.controlled_url, timeout=3).status_code == 410
        rows = source.get_receipts()
        assert sum(r["action"] == "mock_registrar" and r["status"] == "SENT" for r in rows) == 1
        assert any(r["status"] == "CONFIRMED_DOWN" for r in rows)
        # Restart the same run: no rescan of a suspended target, no second ticket.
        TeamPipeline(runtime).tick()
        Coordinator(runtime, source).tick()
        assert len(server.tickets) == 1
        assert len(source.get_receipts()) == len(rows)
    finally:
        server.shutdown()
        server.server_close()


def test_failed_scan_never_becomes_completed_negative(tmp_path, monkeypatch):
    runtime = settings(tmp_path)
    server = start_registrar(runtime.run_dir)
    try:
        pipeline = TeamPipeline(runtime)
        pipeline.tick()
        monkeypatch.setattr("shipper.team_pipeline.scan_capture",
                            lambda _: (_ for _ in ()).throw(RuntimeError("scanner unavailable")))
        with pytest.raises(RuntimeError):
            pipeline.tick()
        row = read_json(pipeline.path)[0]
        assert not row["metadata"]["scan_completed_at"]
        assert not row["metadata"]["scanner"]
        assert scan_label(row["event"], row["metadata"]) == "Scan failed"
        assert server.suspended is False
    finally:
        server.shutdown()
        server.server_close()
