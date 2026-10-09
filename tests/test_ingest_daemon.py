"""Daemon and dashboard regression tests with fake clocks and connections."""
from types import SimpleNamespace

import pytest

import ingest
import threatfeed


def test_long_outage_backoff_stays_capped_and_recovers():
    now = [0.0]
    scheduler = ingest.Scheduler(["urlhaus", "openphish"], clock=lambda: now[0])
    assert scheduler.due() == ["urlhaus", "openphish"]
    scheduler.record("openphish", ok=True)
    for _ in range(1100):
        scheduler.record("urlhaus", ok=False)
    assert scheduler.interval("urlhaus") == 3600
    now[0] = 600
    assert scheduler.due() == ["openphish"]
    scheduler.record("urlhaus", ok=True)
    assert scheduler.interval("urlhaus") == 300


def test_daemon_survives_crashed_cycle_and_resets_schema_only_once():
    now = [0.0]
    attempts = []
    def runner(args, names, reset_schema):
        attempts.append((list(names), reset_schema))
        if len(attempts) == 1:
            raise RuntimeError("offline fixture failure")
        return 0, {name: {"error": ""} for name in names}
    def sleep(seconds):
        now[0] += seconds
    args = SimpleNamespace(feed_names=["urlhaus", "openphish"], interval=0, max_cycles=3)
    assert ingest.run_daemon(args, reset_schema=True, clock=lambda: now[0], sleep=sleep,
                             runner=runner, count_rows=lambda: None, install_signals=False) == 0
    assert attempts == [(["urlhaus", "openphish"], True), (["urlhaus"], False), (["urlhaus"], False)]


def test_run_stats_failure_does_not_undo_successful_ingestion(monkeypatch):
    calls = []
    db = SimpleNamespace(command=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("telemetry unavailable")),
                         close=lambda: calls.append("closed"))
    monkeypatch.setattr(ingest, "connect_clickhouse", lambda: db)
    monkeypatch.setattr(ingest, "ensure_schema", lambda *a, **k: None)
    monkeypatch.setattr(ingest, "drop_duplicates", lambda client, rows: (rows, 0))
    monkeypatch.setattr(ingest, "insert_rows", lambda client, rows: calls.append("inserted") or len(rows))
    monkeypatch.setattr(ingest, "report_table_state", lambda *a: None)
    monkeypatch.setitem(ingest.FEEDS, "openphish", ingest.Feed("openphish", lambda limit: ["fixture"],
                                                             lambda raw, args: [("fixture",)]))
    code, stats = ingest.run_feeds(ingest.parse_args([]), ["openphish"], reset_schema=False)
    assert code == 0 and stats["openphish"]["new"] == 1 and stats["openphish"]["error"] == ""
    assert calls == ["inserted", "closed"]


@pytest.mark.parametrize("exists", [True, False])
def test_dashboard_stats_read_recent_runs_and_close_owned_client(monkeypatch, exists):
    queries, closed = [], []
    results = [[("openphish", 2, 1)], [("phishing", 2)], [("PENDING", 1), ("SCANNED", 1)],
               [(1760011200, "openphish", 3, 2, 1, 1, "", 50)]]
    def query(sql, **kwargs):
        queries.append((sql, kwargs))
        if "system.tables" in sql:
            return SimpleNamespace(first_row=[int(exists)])
        return SimpleNamespace(result_rows=results.pop(0))
    monkeypatch.setattr(threatfeed, "_client", lambda:
                        SimpleNamespace(query=query, close=lambda: closed.append(True)))
    data = threatfeed.get_feed_stats(2)
    assert data["by_feed"] == [{"feed_source": "openphish", "rows": 2, "pending": 1}]
    assert closed == [True]
    if exists:
        assert data["recent_runs"][0]["mapped"] == 2
        assert data["recent_runs"][0]["run_ts"].utcoffset().total_seconds() == 0
        assert queries[-1][1]["parameters"] == {"n": 2}
    else:
        assert data["recent_runs"] == []


def test_smoke_run_restores_both_table_names_on_failure(monkeypatch):
    from tests import smoke_test
    monkeypatch.setenv("THREATS_TABLE", "team_threats")
    monkeypatch.setenv("RUNS_TABLE", "team_runs")
    def fail():
        assert ingest.table_name() == smoke_test.TEST_TABLE
        assert ingest.runs_table_name() == smoke_test.TEST_RUNS_TABLE
        raise RuntimeError("fixture")
    monkeypatch.setattr(smoke_test, "_run", fail)
    with pytest.raises(RuntimeError, match="fixture"):
        smoke_test.run()
    assert ingest.table_name() == "team_threats"
    assert ingest.runs_table_name() == "team_runs"


def test_main_daemon_defaults_to_all_feeds_and_rejects_invalid_options(monkeypatch):
    selected = []
    monkeypatch.setattr(ingest, "load_environment", lambda: None)
    monkeypatch.setattr(ingest, "run_daemon", lambda args, **kwargs:
                        selected.append(args.feed_names) or 0)
    assert ingest.main(["--daemon", "--max-cycles", "1"]) == 0
    assert selected == [list(ingest.FEEDS)]
    for options in (["--max-cycles", "1"], ["--daemon", "--dry-run"],
                    ["--daemon", "--interval", "-1"]):
        assert ingest.main(options) == ingest.EXIT_USAGE
