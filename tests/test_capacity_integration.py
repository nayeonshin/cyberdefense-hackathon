"""Offline regression checks for capacity tools and high-volume deduplication."""
import importlib.util
import ipaddress
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import bench
import ingest
import threatfeed


def test_large_dedup_lookup_chunks_ids_and_preserves_original_order():
    rows = [(f"event-{i:05}",) for i in range(5500)]
    calls = []
    def query(sql, parameters):
        ids = parameters["ids"]
        calls.append(ids)
        assert len(ids) <= ingest.DEDUP_LOOKUP_CHUNK
        return SimpleNamespace(result_rows=[(value,) for value in ids if int(value.split('-')[1]) % 2 == 0])
    fresh, duplicates = ingest.drop_duplicates(SimpleNamespace(query=query), rows + rows[:3])
    assert fresh == rows[1::2]
    assert duplicates == 2753
    assert [len(ids) for ids in calls] == [2000, 2000, 1500]
    assert len({value for ids in calls for value in ids}) == 5500


def test_benchmark_generator_uses_only_reserved_targets_at_large_volume():
    rows = bench.generate_rows(30_000, seed=3)
    network = ipaddress.ip_network("198.51.100.0/24")
    assert all(ipaddress.ip_address(row[3]) in network if row[3] else row[2].endswith('.invalid') for row in rows)
    assert len({row[0] for row in rows}) == len(rows)
    assert rows[:100] == bench.generate_rows(30_000, seed=3)[:100]


def test_benchmark_percentiles_use_nearest_rank():
    assert bench._percentile([1, 2, 3, 4, 5], 50) == 3
    assert bench._percentile([1, 2], 50) == 1
    assert bench._percentile([1, 2, 3, 4, 5], 95) == 5


def test_benchmark_refuses_configured_live_tables_before_connecting(monkeypatch):
    monkeypatch.setenv("THREATS_TABLE", "team_threats")
    monkeypatch.setenv("RUNS_TABLE", "team_runs")
    monkeypatch.setenv("EVENTS_TABLE", "team_events")
    monkeypatch.setattr(ingest, "connect_clickhouse", lambda: pytest.fail("opened a connection"))
    for table in ("incoming_threats", "team_threats", "team_runs", "team_events"):
        with pytest.raises(ValueError, match="live table"):
            bench.run_bench(1, 1, table=table)


def test_benchmark_never_replaces_existing_table_and_closes_client(monkeypatch):
    closed = []
    client = SimpleNamespace(server_version="fixture", query=lambda *a, **k: SimpleNamespace(first_row=[1]),
                             command=lambda *a, **k: pytest.fail("modified an existing table"),
                             close=lambda: closed.append(True))
    monkeypatch.setattr(ingest, "connect_clickhouse", lambda: client)
    with pytest.raises(ValueError, match="existing benchmark table"):
        bench.run_bench(1, 1, table="existing_bench")
    assert closed == [True]


def test_volume_import_does_not_change_table_settings_or_working_directory(monkeypatch):
    monkeypatch.setenv("RUNS_TABLE", "team_runs")
    previous = Path.cwd()
    spec = importlib.util.spec_from_file_location("volume_import_check", Path(__file__).with_name("volume_test.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert os.environ["RUNS_TABLE"] == "team_runs" and Path.cwd() == previous
    assert module.TEST_RUNS_TABLE.startswith("ingest_runs_volume_test_")


@pytest.mark.parametrize("span,busy_ms,expected", [(3600, 4000, 6.0), (599, 0, None), (600, 4000, 36.0)])
def test_live_throughput_excludes_cold_start_and_handles_short_or_zero_busy_time(monkeypatch, span, busy_ms, expected):
    results = [[], [], [], [], [("urlhaus", 3, 1, 3000, 56, 94, busy_ms, span, 50)]]
    def query(sql, **kwargs):
        if "system.tables" in sql:
            return SimpleNamespace(first_row=[1])
        return SimpleNamespace(result_rows=results.pop(0))
    monkeypatch.setattr(threatfeed, "_client", lambda: SimpleNamespace(query=query, close=lambda: None))
    stats = threatfeed.get_feed_stats()["throughput"][0]
    assert stats["failed_runs"] == 1 and stats["steady_new_per_hour"] == expected
    assert stats["processed_per_s"] == (750.0 if busy_ms else None)
