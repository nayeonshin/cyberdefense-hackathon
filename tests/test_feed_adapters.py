"""Offline feed regression tests; never contact feed servers or their targets."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

import ingest
from brain import clickhouse as store


NOW = datetime(2026, 10, 9, 12, tzinfo=timezone.utc)


def ioc(value, kind="url", **changes):
    return {"id": "42", "ioc": value, "ioc_type": kind,
            "first_seen": "2026-10-09 12:00:00 UTC", "threat_type": "botnet_cc", **changes}


def test_openphish_identity_survives_repoll_and_validates_timestamp_and_url():
    url = "https://demo.example/login?continue=1"
    first = ingest.map_openphish([{"url": url, "fetched_at": NOW}])[0]
    later = ingest.map_openphish([{"url": url, "fetched_at": NOW + timedelta(days=1)}])[0]
    assert first[0] == later[0] and first[0].startswith("openphish-")
    assert first[1:] == (url, "demo.example", "", NOW, "phishing", "PENDING", "openphish")
    assert ingest.map_openphish([
        {"url": url, "fetched_at": "not a timestamp"},
        {"url": "https://demo.example:99999/", "fetched_at": NOW},
        {"url": "file:///tmp/page", "fetched_at": NOW}, None,
    ]) == []


@pytest.mark.parametrize("value,kind", [
    ("ftp://demo.example/a", "url"), ("https://demo.example:bad/", "url"),
    ("192.0.2.1:0", "ip:port"), ("192.0.2.1:65536", "ip:port"),
    ("not-an-ip:80", "ip:port"), ("abcdef", "sha256_hash"),
])
def test_threatfox_rejects_unscannable_or_malformed_candidates(value, kind):
    assert ingest.map_threatfox([ioc(value, kind)]) == []


def test_threatfox_maps_ipv6_and_normalizes_threat_categories():
    rows = ingest.map_threatfox([
        ioc("[2001:db8::1]:443", "ip:port"),
        ioc("https://demo.example/a", id="43", threat_type="payload_delivery"),
    ])
    assert rows[0] == ("threatfox-42", "http://[2001:db8::1]:443", "2001:db8::1",
                       "2001:db8::1", NOW, "c2", "PENDING", "threatfox")
    assert rows[1][5] == "malware_download"


def test_feed_selection_does_not_hide_typos():
    assert ingest.parse_feed_names("OPENPHISH, threatfox,openphish") == ["openphish", "threatfox"]
    assert ingest.parse_feed_names("all") == list(ingest.FEEDS)
    for value in ("", "all,nope", "nope"):
        with pytest.raises(ValueError):
            ingest.parse_feed_names(value)


@pytest.mark.parametrize("source,listed", [("urlhaus", True), ("openphish", True),
                                           ("threatfox", True), ("demo", False)])
def test_feed_provenance_reaches_scanner_without_changing_contract(source, listed):
    db = SimpleNamespace(command=lambda *a, **k: None, query=lambda *a, **k:
                         SimpleNamespace(result_rows=[("id", "https://demo.example/", NOW, source)]))
    event = store.get_pending_events(client=db)[0]
    assert event.pop("listed_on_feed") is listed
    assert set(event) == set(store.EVENT_COLUMNS)


def test_multifeed_poll_preserves_healthy_feed_when_another_fails(monkeypatch, capsys):
    def unavailable(limit):
        raise RuntimeError("fixture unavailable")

    monkeypatch.setitem(ingest.FEEDS, "urlhaus", ingest.Feed("urlhaus", unavailable, lambda *a: []))
    monkeypatch.setitem(ingest.FEEDS, "openphish", ingest.Feed("openphish",
        lambda limit: [{"url": "https://demo.example/", "fetched_at": NOW}],
        lambda raw, args: ingest.map_openphish(raw)))
    monkeypatch.setattr(ingest, "connect_clickhouse", lambda: pytest.fail("dry run opened a database"))
    args = ingest.parse_args(["--feeds", "urlhaus,openphish", "--dry-run"])
    args.feed_names = ingest.parse_feed_names(args.feeds)
    assert ingest.run_once(args, reset_schema=False) == ingest.EXIT_OK
    summary = capsys.readouterr().out
    assert "urlhaus: fetched=0 mapped=0" in summary
    assert "openphish: fetched=1 mapped=1" in summary


@pytest.mark.parametrize("name,raw", [
    ("openphish", [{"url": "not a URL", "fetched_at": NOW}]),
    ("threatfox", [ioc("https://demo.example/", first_seen="broken")]),
])
def test_all_invalid_new_feed_candidates_fail_loudly(monkeypatch, name, raw):
    feed = ingest.FEEDS[name]
    monkeypatch.setitem(ingest.FEEDS, name, ingest.Feed(name, lambda limit: raw, feed.map))
    args = ingest.parse_args(["--feeds", name, "--dry-run"])
    args.feed_names = [name]
    assert ingest.run_once(args, reset_schema=False) == ingest.EXIT_NOTHING_MAPPED


def test_fetches_use_feed_endpoints_and_limit_without_visiting_targets(monkeypatch):
    calls = []
    def get(url, **kwargs):
        calls.append((url, kwargs))
        return SimpleNamespace(raise_for_status=lambda: None,
                               text="https://demo.example/one\n\nhttps://demo.example/two\n")

    def post(url, **kwargs):
        calls.append((url, kwargs))
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"query_status": "ok", "data": [
            ioc("https://demo.example/old", first_seen="2026-10-08 12:00:00 UTC"),
            ioc("https://demo.example/new"), ioc("abc", "md5_hash"), None]})

    monkeypatch.setattr(ingest.requests, "get", get)
    monkeypatch.setattr(ingest.requests, "post", post)
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "fixture-key")
    assert len(ingest._fetch_openphish(1)) == 1
    assert ingest._fetch_threatfox(1)[0]["ioc"] == "https://demo.example/new"
    assert [call[0] for call in calls] == [ingest.OPENPHISH_FEED_URL, ingest.THREATFOX_API_URL]
    assert calls[1][1]["headers"] == {"Auth-Key": "fixture-key"}


def test_threatfox_non_object_json_is_a_feed_failure(monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "fixture-key")
    monkeypatch.setattr(ingest.requests, "post", lambda *a, **k:
                        SimpleNamespace(raise_for_status=lambda: None, json=lambda: []))
    with pytest.raises(RuntimeError, match="non-object"):
        ingest._fetch_threatfox(5)
