from copy import deepcopy
from datetime import datetime, timezone

import pytest

from shipper.motion_model import motion_state
from tests.test_presentation import app_fixture


def evidence():
    record = {"event": {"event_id": "evt", "target_url": "https://owned.example.invalid",
                         "semgrep_detected": True, "confidence_score": .6, "evidence": '<form action="x">',
                         "action_status": "PENDING"},
              "metadata": {"ingested_at": "2026-10-09T19:00:00Z", "scan_completed_at": "2026-10-09T19:00:05Z", "scanner": "semgrep"}}
    rows = [dict(event_id="evt", target_url=record["event"]["target_url"], dry_run=False,
                 status=status, created_at=f"2026-10-09T19:00:{second}Z", action=action, detail="saved")
            for status, second, action in [("SENT", "08", "mock_registrar"), ("CONFIRMED_DOWN", "15", "confirm")]]
    return record, rows


def test_replay_requires_complete_ordered_real_evidence():
    record, rows = evidence()
    state = motion_state(record, rows)
    assert state["replay"] and state["duration"] == 15
    assert state["latest"] == 3 and all(s["reached"] for s in state["stages"])
    assert state["target"] == "hxxps://owned[.]example[.]invalid"
    for flags in ({"simulated": True}, {"historical": True}, {"degraded": True}):
        assert not motion_state(record, rows, **flags)["replay"]
    for bad in ("other-event",):
        altered = deepcopy(rows); altered[0]["event_id"] = bad
        assert not motion_state(record, altered)["replay"]
    altered = deepcopy(rows); altered[0]["target_url"] = "https://another.invalid"
    assert not motion_state(record, altered)["replay"]
    altered = deepcopy(rows); altered[0]["dry_run"] = True
    assert not motion_state(record, altered)["replay"]
    altered = deepcopy(rows); altered[0]["created_at"] = "2026-10-09T18:59:59Z"
    assert not motion_state(record, altered)["replay"]
    record["metadata"]["scanner"] = "fixture"
    assert not motion_state(record, rows)["replay"]


@pytest.mark.parametrize("status,phase", [("FAILED", "dispatch-failed"), ("SINK", "saved-test"),
                                        ("SKIPPED", "skipped"), ("STILL_UP", "reachable")])
def test_receipt_failures_never_complete_the_path(status, phase):
    record, rows = evidence()
    rows = [{**rows[0], "status": status}]
    state = motion_state(record, rows)
    assert state["phase"] == phase and not state["replay"]
    assert not state["stages"][2]["reached"] and not state["stages"][3]["reached"]


def test_scan_negative_pending_failed_and_historical_remain_distinct():
    record, rows = evidence()
    assert motion_state(record, rows, historical=True)["phase"] == "historical"
    record["event"]["semgrep_detected"] = False
    state = motion_state(record, [])
    assert state["status"] == "No rule matched" and state["stages"][2]["detail"] == "Not applicable"
    record["metadata"]["scan_completed_at"] = None
    assert motion_state(record, [])["phase"] == "pending"
    record["metadata"]["scan_error"] = "failure"
    state = motion_state(record, [])
    assert state["phase"] == "scan-failed" and state["confidence"] == "—"


@pytest.mark.parametrize("invalid", ["bad time", "2099-01-01T00:00:00Z", None])
def test_invalid_or_future_evidence_cannot_advance_replay(invalid):
    record, rows = evidence()
    record["metadata"]["scan_completed_at"] = invalid
    state = motion_state(record, rows, now=datetime(2026, 10, 9, 23, tzinfo=timezone.utc))
    assert not state["stages"][1]["reached"] and not state["replay"]


def test_fixture_receipts_never_claim_live_actions():
    record, rows = evidence()
    state = motion_state(record, rows, simulated=True)
    assert state["receipt"] is None and not state["replay"]
    assert not any(s["reached"] for s in state["stages"][2:])


def test_app_motion_updates_are_read_only_and_keep_selection(tmp_path, monkeypatch):
    captured = []
    monkeypatch.setattr("shipper.motion.render_motion", lambda payload: captured.append(payload))
    app, source = app_fixture(tmp_path, monkeypatch)
    original = deepcopy(source.fixture)
    app.query_params["event"] = "demo-102"
    app.run(); app.run()
    assert not app.exception
    assert captured[-1]["event_id"] == "demo-102" and captured[-1]["simulated"]
    assert not captured[-1]["replay"]
    assert source.fixture == original
    source.get_events = lambda: (_ for _ in ()).throw(ConnectionError())
    app.run()
    assert captured[-1]["degraded"] and captured[-1]["event_id"] == "demo-102"
