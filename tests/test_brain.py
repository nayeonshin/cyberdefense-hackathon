import functools
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from brain import decide as decide_mod
from brain.decide import FETCH_FAILED, REJECTED, VERIFIED, confidence
from brain.fetcher import fetch_target
from brain.pipeline import new_event, process_event
from brain.scan import Finding, ScanError, _semgrep_bin

DEMO_SITES = Path(__file__).resolve().parent.parent / "demo-sites"

try:
    _semgrep_bin()
    HAVE_SEMGREP = True
except ScanError:
    HAVE_SEMGREP = False
needs_semgrep = pytest.mark.skipif(not HAVE_SEMGREP, reason="semgrep not installed")


@pytest.fixture(scope="module")
def demo_server():
    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(DEMO_SITES))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture
def allow_private(monkeypatch):
    monkeypatch.setenv("BRAIN_ALLOW_PRIVATE", "1")


def finding(rule, weight):
    return Finding(rule=rule, category="c", weight=weight, file="f.js", line=1, end_line=1, snippet="x")


def test_confidence_combines_distinct_rules():
    assert confidence([]) == 0.0
    assert confidence([finding("a", 0.6)]) == 0.6
    assert confidence([finding("a", 0.6), finding("a", 0.6)]) == 0.6
    assert confidence([finding("a", 0.6), finding("b", 0.5)]) == 0.8
    assert confidence([finding("a", 0.6)], listed_on_feed=True) == 0.75
    assert confidence([finding("a", 0.9), finding("b", 0.9), finding("c", 0.9)]) == 0.99


def test_private_addresses_are_refused(tmp_path, demo_server, monkeypatch):
    monkeypatch.delenv("BRAIN_ALLOW_PRIVATE", raising=False)
    capture = fetch_target(f"{demo_server}/phish/", tmp_path)
    assert not capture.ok
    assert "non-public" in capture.error


def test_fetcher_extracts_scripts(tmp_path, demo_server, allow_private):
    phish = fetch_target(f"{demo_server}/phish/", tmp_path / "phish")
    assert phish.ok
    assert {"page.html", "ext_0.js"} <= set(phish.files)
    benign = fetch_target(f"{demo_server}/benign/", tmp_path / "benign")
    assert {"page.html", "inline_0.js"} <= set(benign.files)


def test_dead_url_is_fetch_failed(allow_private):
    event, findings = process_event(new_event("http://127.0.0.1:9/nothing-here"))
    assert event["action_status"] == FETCH_FAILED
    assert event["semgrep_detected"] is False
    assert findings == []


@needs_semgrep
def test_phishing_demo_site_is_verified(demo_server, allow_private):
    original = new_event(f"{demo_server}/phish/")
    event, findings = process_event(original)
    assert event["action_status"] == VERIFIED
    assert event["semgrep_detected"] is True
    assert event["confidence_score"] >= decide_mod.THRESHOLD
    assert {f.rule for f in findings} == {"cross-origin-credential-post", "telegram-bot-exfil", "fake-login-form"}
    assert "Semgrep rule `" in event["evidence"]
    # Member 1's fields pass through untouched, and the contract's keys are all there.
    for key in ("event_id", "target_url", "timestamp", "proof_url"):
        assert event[key] == original[key]
    assert set(event) == set(original)


@needs_semgrep
def test_benign_lookalike_is_rejected(demo_server, allow_private):
    event, findings = process_event(new_event(f"{demo_server}/benign/"))
    assert event["action_status"] == REJECTED
    assert event["semgrep_detected"] is False
    assert findings == []


@needs_semgrep
def test_service_scan(demo_server, allow_private):
    from fastapi.testclient import TestClient

    from brain.service import app

    client = TestClient(app)
    assert client.get("/health").json() == {"ok": True}
    body = {"event_id": "evt-1", "target_url": f"{demo_server}/phish/", "timestamp": "2026-10-09T11:00:00Z"}
    result = client.post("/scan", json=body).json()
    assert result["event_id"] == "evt-1"
    assert result["action_status"] == VERIFIED
    assert result["findings"]
    assert "listed_on_feed" not in result


def test_service_requires_api_key_when_set(monkeypatch):
    from fastapi.testclient import TestClient

    from brain.service import app

    monkeypatch.setenv("BRAIN_API_KEY", "s3cret")
    client = TestClient(app)
    body = {"event_id": "evt-1", "target_url": "http://127.0.0.1:9/x", "timestamp": "2026-10-09T11:00:00Z"}
    assert client.post("/scan", json=body).status_code == 401
    assert client.post("/scan", json=body, headers={"X-API-Key": "wrong"}).status_code == 401
    ok = client.post("/scan", json=body, headers={"X-API-Key": "s3cret"})
    assert ok.status_code == 200
    assert ok.json()["action_status"] == FETCH_FAILED
    assert client.get("/health").status_code == 200
