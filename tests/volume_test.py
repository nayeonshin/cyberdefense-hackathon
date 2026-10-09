#!/usr/bin/env python3
"""Volume / velocity test for Member 1's ClickHouse layer.

    .venv/bin/python tests/volume_test.py                 # 100k rows (default)
    .venv/bin/python tests/volume_test.py --rows 1000000 --batch 50000

Two separate claims, tested separately -- never conflate them:

  A. CAPACITY (synthetic, offline): the real ingest path (dedup + bulk insert)
     sustains at least MIN_ROWS_PER_S into ClickHouse, Member 2's query stays
     under MAX_QUERY_MS at that volume, and dedup still holds. Uses the isolated
     table `incoming_threats_bench_<uuid>`, dropped afterwards.
  B. LIVE-FEED RATE reporting: `get_feed_stats()["throughput"]` derives correct
     per-feed rates from `ingest_runs`, excludes the cold-start backlog, and
     never counts benchmark rows. Uses a unique `ingest_runs_volume_test_<uuid>`.

Never touches `incoming_threats` or `ingest_runs`. Needs a reachable
ClickHouse (clickhouse.env); no Auth-Key, no feed traffic.

The floors are deliberately conservative (a laptop measures 90k-200k rows/s,
see MEMBER1_PLAN.md section 10); they catch regressions such as row-at-a-time
inserts, not small slowdowns. Override with VOLUME_MIN_ROWS_PER_S /
VOLUME_MAX_QUERY_MS on slow CI.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
TEST_RUNS_TABLE = "ingest_runs_volume_test_" + uuid.uuid4().hex

import bench  # noqa: E402
import ingest  # noqa: E402
import threatfeed  # noqa: E402

MIN_ROWS_PER_S = float(os.getenv("VOLUME_MIN_ROWS_PER_S", "10000"))
MAX_QUERY_MS = float(os.getenv("VOLUME_MAX_QUERY_MS", "2000"))

failures: list[str] = []
passes = 0


def check(condition: bool, label: str) -> None:
    global passes
    if condition:
        passes += 1
        print(f"  [PASS] {label}")
    else:
        failures.append(label)
        print(f"  [FAIL] {label}")


def raises_value_error(fn, *args, **kwargs) -> bool:
    try:
        fn(*args, **kwargs)
    except ValueError:
        return True
    return False


# --------------------------------------------------------------------------- #
# 1. Generator (no DB)
# --------------------------------------------------------------------------- #


def generator_checks() -> None:
    print("\n1. synthetic generator (offline)")
    rows = bench.generate_rows(5000, seed=7)
    check(len(rows) == 5000, "generates exactly n rows")
    check(rows == bench.generate_rows(5000, seed=7), "deterministic for the same seed")
    check(rows != bench.generate_rows(5000, seed=8), "different seed -> different rows")
    check(all(len(r) == len(ingest.COLUMN_NAMES) for r in rows), "rows match COLUMN_NAMES width")
    check(len({r[0] for r in rows}) == 5000, "event_ids unique")
    check(all(r[7] == bench.BENCH_FEED_SOURCE for r in rows), "feed_source == 'bench'")
    check(all(r[6] == "PENDING" for r in rows), "takedown_status == PENDING")
    check(all(r[2].endswith(".invalid") or r[2].startswith("198.51.") for r in rows),
          "only reserved .invalid domains / TEST-NET IPs (no real targets)")
    check(all((r[3] == r[2]) == r[2].startswith("198.51.") for r in rows),
          "ip_address filled exactly for IP-literal hosts")
    check(all(r[4].tzinfo is not None for r in rows), "timestamps UTC-aware")
    counts: dict[str, int] = {}
    for r in rows:
        counts[r[2]] = counts.get(r[2], 0) + 1
    top = max(counts.values())
    check(top >= 50 and top < 2500, f"skewed campaign shape (top domain {top}/5000)")
    check({r[5] for r in rows} == {"malware_download", "phishing", "c2"}, "all threat types present")
    for bad in (0, -1, True, "10"):
        check(raises_value_error(bench.generate_rows, bad), f"generate_rows({bad!r}) -> ValueError")


# --------------------------------------------------------------------------- #
# 2. Capacity (DB, synthetic)
# --------------------------------------------------------------------------- #


def capacity_checks(rows: int, batch: int) -> None:
    print(f"\n2. capacity: {rows:,} rows in batches of {batch:,} (incoming_threats_bench)")
    check(raises_value_error(bench.run_bench, 10, 10, table="incoming_threats"),
          "refuses the live incoming_threats table")
    check(raises_value_error(bench.run_bench, 0, 10), "rows=0 -> ValueError")

    client = ingest.connect_clickhouse()
    try:
        live_before = client.query("SELECT count() FROM system.tables WHERE database = "
                                   "currentDatabase() AND name = 'incoming_threats'").first_row[0]
        live_rows = (client.query("SELECT count() FROM incoming_threats").first_row[0]
                     if live_before else None)

        r = bench.run_bench(rows, batch)
        bench.print_report(r)

        for label, ok in r["checks"].items():
            check(ok, f"bench integrity: {label}")
        check(r["inserted"] == rows, f"inserted {r['inserted']:,} == {rows:,}")
        check(r["rows_per_s"] >= MIN_ROWS_PER_S,
              f"VELOCITY: {r['rows_per_s']:,.0f} rows/s end-to-end >= floor {MIN_ROWS_PER_S:,.0f}")
        check(r["query_ms"]["p50"] <= MAX_QUERY_MS,
              f"Member 2 query p50 {r['query_ms']['p50']:.0f} ms <= {MAX_QUERY_MS:.0f} ms "
              f"at {rows:,} rows")
        check(r["batches"] == -(-rows // batch), f"{r['batches']} batches (one insert per poll)")

        gone = client.query("SELECT count() FROM system.tables WHERE database = "
                            "currentDatabase() AND name = {t:String}",
                            parameters={"t": r["table"]}).first_row[0]
        check(gone == 0, "bench table dropped afterwards")
        if live_rows is not None:
            after = client.query("SELECT count() FROM incoming_threats").first_row[0]
            check(after == live_rows, f"live incoming_threats untouched ({live_rows} rows)")
        bench_runs = client.query("SELECT count() FROM system.tables WHERE database = "
                                  "currentDatabase() AND name = {t:String}",
                                  parameters={"t": TEST_RUNS_TABLE}).first_row[0]
        check(bench_runs == 0, "bench writes no ingest_runs telemetry")
    finally:
        client.close()


# --------------------------------------------------------------------------- #
# 3. Live-feed throughput reporting (DB, isolated runs table)
# --------------------------------------------------------------------------- #


def throughput_checks() -> None:
    print(f"\n3. live-feed throughput from ingest_runs ({TEST_RUNS_TABLE})")
    client = ingest.connect_clickhouse()
    threats = "incoming_threats_rate_test_" + uuid.uuid4().hex
    previous = os.environ.get("THREATS_TABLE")
    os.environ["THREATS_TABLE"] = threats
    try:
        ingest.ensure_schema(client, table=threats)
        client.command(f"DROP TABLE IF EXISTS {TEST_RUNS_TABLE}")
        check(threatfeed.get_feed_stats()["throughput"] == [], "no runs table -> throughput == []")

        client.command(ingest.CREATE_RUNS_TABLE_TEMPLATE.format(table=TEST_RUNS_TABLE))
        t0 = datetime(2026, 10, 9, 12, 0, 0, tzinfo=timezone.utc)
        cols = ingest.RUN_COLUMN_NAMES
        # urlhaus: cold start of 50 (backlog), then 4 + 2 new over 1 h -> 6/h steady.
        # threatfox: one run only -> no steady rate. openphish: a failure counted.
        rows = [
            (t0, "urlhaus", 1000, 50, 50, 0, "", 2000),
            (t0 + timedelta(minutes=30), "urlhaus", 1000, 50, 4, 46, "", 1000),
            (t0 + timedelta(hours=1), "urlhaus", 1000, 50, 2, 48, "", 1000),
            (t0, "threatfox", 20, 20, 19, 1, "", 500),
            (t0, "openphish", 10, 10, 10, 0, "", 250),
            (t0 + timedelta(minutes=5), "openphish", 0, 0, 0, 0, "timeout", 750),
        ]
        client.insert(TEST_RUNS_TABLE, rows, column_names=cols)

        tp = {r["feed_source"]: r for r in threatfeed.get_feed_stats()["throughput"]}
        check(set(tp) == {"urlhaus", "threatfox", "openphish"}, "one row per feed")
        u = tp["urlhaus"]
        check((u["runs"], u["fetched"], u["inserted"], u["duplicates"]) == (3, 3000, 56, 94),
              f"urlhaus totals {u['runs']}/{u['fetched']}/{u['inserted']}/{u['duplicates']}")
        check(u["busy_s"] == 4.0 and u["processed_per_s"] == 750.0,
              f"urlhaus processed_per_s = 3000 / 4.0 s = {u['processed_per_s']}")
        check(u["span_s"] == 3600 and u["steady_new_per_hour"] == 6.0,
              f"urlhaus steady_new_per_hour excludes 50-row cold start: {u['steady_new_per_hour']}")
        check(tp["threatfox"]["steady_new_per_hour"] is None,
              "single run -> steady rate None (not a fake number)")
        o = tp["openphish"]
        check(o["failed_runs"] == 1 and o["runs"] == 2, "failed runs counted")
        check(o["steady_new_per_hour"] is None,
              f"5-min span < {threatfeed.STEADY_RATE_MIN_SPAN_S}s -> None")
        order = [r["feed_source"] for r in threatfeed.get_feed_stats()["throughput"]]
        check(order == ["urlhaus", "threatfox", "openphish"], f"ordered by inserted desc: {order}")
    finally:
        try:
            client.command(f"DROP TABLE IF EXISTS {TEST_RUNS_TABLE}")
            client.command(f"DROP TABLE IF EXISTS {threats}")
        finally:
            client.close()
            if previous is None:
                os.environ.pop("THREATS_TABLE", None)
            else:
                os.environ["THREATS_TABLE"] = previous


# --------------------------------------------------------------------------- #
# 4. Dedup lookup above the HTTP field-size limit (regression)
# --------------------------------------------------------------------------- #


def dedup_chunk_checks() -> None:
    print("\n4. drop_duplicates with > http_max_field_value_size worth of ids (regression)")
    table = "incoming_threats_volume_test_" + uuid.uuid4().hex
    client = ingest.connect_clickhouse()
    try:
        client.command(f"DROP TABLE IF EXISTS {table}")
        ingest.ensure_schema(client, table=table)
        rows = bench.generate_rows(25_000, seed=3)
        ingest.insert_rows(client, rows[:12_000], table=table)
        fresh, dups = ingest.drop_duplicates(client, rows, table=table)
        check((len(fresh), dups) == (13_000, 12_000),
              f"25k-id lookup works: {len(fresh)} new, {dups} duplicates")
        check({r[0] for r in fresh} == {r[0] for r in rows[12_000:]}, "exactly the unseen ids survive")
    finally:
        client.command(f"DROP TABLE IF EXISTS {table}")
        client.close()


def _run(rows: int, batch: int) -> int:
    ingest.load_environment()
    generator_checks()
    for name, fn, args in (
        ("capacity", capacity_checks, (rows, batch)),
        ("throughput", throughput_checks, ()),
        ("dedup chunking", dedup_chunk_checks, ()),
    ):
        try:
            fn(*args)
        except Exception as exc:  # noqa: BLE001 -- surface as a failed check
            failures.append(f"{name} section aborted: {type(exc).__name__}: {exc}")
            print(f"  [FAIL] {name} section aborted: {type(exc).__name__}: {exc}")

    print()
    print("=" * 60)
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED ({passes} passed):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"ALL VOLUME CHECKS PASSED ({passes} checks)")
    return 0


def test_volume() -> None:  # pytest entrypoint
    if os.getenv("RUN_VOLUME_TESTS") != "1":
        import pytest
        pytest.skip("set RUN_VOLUME_TESTS=1 for local ClickHouse capacity tests")
    assert run() == 0, failures


def run(rows: int = bench.DEFAULT_ROWS, batch: int = bench.DEFAULT_BATCH) -> int:
    global passes
    passes = 0
    failures.clear()
    previous = os.environ.get("RUNS_TABLE")
    os.environ["RUNS_TABLE"] = TEST_RUNS_TABLE
    try:
        return _run(rows, batch)
    finally:
        if previous is None:
            os.environ.pop("RUNS_TABLE", None)
        else:
            os.environ["RUNS_TABLE"] = previous


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rows", type=int, default=bench.DEFAULT_ROWS)
    parser.add_argument("--batch", type=int, default=bench.DEFAULT_BATCH)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO if args.verbose else logging.CRITICAL)
    sys.exit(run(args.rows, args.batch))
