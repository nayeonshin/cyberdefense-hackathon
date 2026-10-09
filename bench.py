#!/usr/bin/env python3
"""
bench -- offline capacity benchmark for the ClickHouse threat layer.

    .venv/bin/python ingest.py --bench                       # 100k rows, 10k per batch
    .venv/bin/python ingest.py --bench --rows 1000000 --batch 50000
    .venv/bin/python bench.py --rows 200000                  # same thing, direct

What this measures -- and what it does NOT:

  * It measures **pipeline capacity**: how many threat rows per second the real
    ingest path (`ingest.drop_duplicates` + `ingest.insert_rows`, the same
    functions the live poller uses) can push into ClickHouse, and how fast the
    Member 2 query (`threatfeed.get_pending_targets`) answers at that volume.
  * It does NOT measure how fast the live feeds emit data. URLhaus / OpenPhish /
    ThreatFox are low-volume by nature; their real rate comes from the
    `ingest_runs` telemetry (`threatfeed.py --stats`, "live feed throughput").
    Keep the two numbers apart when presenting them.

Safety:
  * Rows are synthetic and deterministic (seeded), use `feed_source='bench'`,
    reserved `.invalid` domains / TEST-NET IPs, and `bench-` event ids.
  * They go into a unique isolated table (`incoming_threats_bench_<uuid>`) that is
    dropped afterwards unless `--keep`. The live `incoming_threats` table is
    refused outright.
  * Nothing is written to `ingest_runs`, so synthetic volume can never inflate
    the live-feed throughput numbers.
"""

from __future__ import annotations

import argparse
import logging
import math
import os
import random
import statistics
import sys
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

import ingest

log = logging.getLogger("bench")

BENCH_TABLE = "incoming_threats_bench"
BENCH_FEED_SOURCE = "bench"
DEFAULT_ROWS = 100_000
DEFAULT_BATCH = 10_000
DEFAULT_SEED = 1
QUERY_REPEATS = 5
# Threat mix roughly shaped like the live feeds (URLhaus is mostly malware_download).
THREAT_WEIGHTS: tuple[tuple[str, int], ...] = (
    ("malware_download", 70),
    ("phishing", 20),
    ("c2", 10),
)
# Base time for synthetic `timestamp`s; one row per second going forward.
BENCH_EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# Synthetic data
# --------------------------------------------------------------------------- #


def generate_rows(n: int, *, seed: int = DEFAULT_SEED) -> list[tuple[Any, ...]]:
    """Return `n` deterministic synthetic rows in `ingest.COLUMN_NAMES` order.

    Domains follow a skewed (Zipf-like) distribution, so a few "campaigns" own
    many URLs -- the shape `get_pending_targets()` ranks on. ~20 % of hosts are
    TEST-NET IP literals (RFC 5737) and fill `ip_address`, the rest use the
    reserved `.invalid` TLD (RFC 2606), so nothing here is a real target.
    Same `n` and `seed` -> identical rows.
    """
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValueError(f"n must be an int >= 1 (got {n!r})")
    rng = random.Random(seed)
    domain_pool = max(10, n // 25)
    names = [t for t, _ in THREAT_WEIGHTS]
    weights = [w for _, w in THREAT_WEIGHTS]

    rows: list[tuple[Any, ...]] = []
    for i in range(n):
        # Pareto heavy tail: low ranks are picked far more often (top domain
        # ~9 % of rows, long tail of one-URL domains), like real campaigns.
        rank = min(int((rng.paretovariate(1.0) - 1) * 10), domain_pool - 1)
        if rank % 5 == 4:
            host = f"198.51.100.{rank % 254 + 1}"
            ip = host
        else:
            host = f"campaign-{rank}.bench.invalid"
            ip = ""
        threat = rng.choices(names, weights)[0]
        rows.append(
            (
                f"bench-{seed}-{i}",
                f"http://{host}/p/{i}.bin",
                host,
                ip,
                BENCH_EPOCH + timedelta(seconds=i),
                threat,
                ingest.DEFAULT_TAKEDOWN_STATUS,
                BENCH_FEED_SOURCE,
            )
        )
    return rows


# --------------------------------------------------------------------------- #
# Benchmark
# --------------------------------------------------------------------------- #


def _percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile; 0.0 for an empty list."""
    if not values:
        return 0.0
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, math.ceil(pct / 100 * len(ordered)) - 1))
    return ordered[k]


@contextmanager
def _threats_table(table: str) -> Iterator[None]:
    """Point THREATS_TABLE at `table` for the duration (threatfeed reads it)."""
    previous = os.environ.get(ingest.TABLE_ENV_VAR)
    os.environ[ingest.TABLE_ENV_VAR] = table
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(ingest.TABLE_ENV_VAR, None)
        else:
            os.environ[ingest.TABLE_ENV_VAR] = previous


def run_bench(
    rows: int = DEFAULT_ROWS,
    batch: int = DEFAULT_BATCH,
    *,
    seed: int = DEFAULT_SEED,
    table: str | None = None,
    keep: bool = False,
) -> dict[str, Any]:
    """Generate `rows` synthetic threats and push them through the ingest path.

    Each batch is one simulated poll: `drop_duplicates` (chunked parameterized
    IN-lookups) then `insert_rows` (one bulk insert) -- exactly what `run_feeds`
    does per feed. Afterwards the table is checked for integrity, the Member 2
    query is timed, and the first batch is re-sent to prove dedup at volume.

    Returns a dict of measurements plus `checks` ({label: bool}); `ok` is True
    only when every check passed. Raises ValueError on bad arguments or when
    `table` is the live threats table.
    """
    for label, value in (("rows", rows), ("batch", batch)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"{label} must be an int >= 1 (got {value!r})")
    table = ingest.table_name(table or f"{BENCH_TABLE}_{uuid.uuid4().hex}")
    if table in {ingest.TABLE_NAME, ingest.table_name(), ingest.runs_table_name(),
                  ingest.table_name(os.getenv("EVENTS_TABLE", "events"))}:
        raise ValueError(f"refusing to benchmark into the live table {table!r}")

    import threatfeed  # local import: threatfeed imports ingest

    t0 = time.perf_counter()
    data = generate_rows(rows, seed=seed)
    gen_s = time.perf_counter() - t0
    log.info("Generated %d synthetic rows in %.2f s", rows, gen_s)

    client = ingest.connect_clickhouse()
    created = False
    result: dict[str, Any] = {
        "table": table,
        "rows": rows,
        "batch": batch,
        "seed": seed,
        "server_version": client.server_version,
        "generate_s": gen_s,
    }
    try:
        exists = client.query(
            "SELECT count() FROM system.tables WHERE database = currentDatabase() AND name = {t:String}",
            parameters={"t": table},
        ).first_row[0]
        if exists:
            raise ValueError(f"refusing to replace existing benchmark table {table!r}")
        ingest.ensure_schema(client, table=table)
        created = True

        insert_lat: list[float] = []
        dedup_lat: list[float] = []
        inserted = 0
        wall0 = time.perf_counter()
        for start in range(0, rows, batch):
            chunk = data[start : start + batch]
            t = time.perf_counter()
            fresh, _dups = ingest.drop_duplicates(client, chunk, table=table)
            dedup_lat.append(time.perf_counter() - t)
            t = time.perf_counter()
            inserted += ingest.insert_rows(client, fresh, table=table)
            insert_lat.append(time.perf_counter() - t)
        wall = time.perf_counter() - wall0
        insert_total = sum(insert_lat)

        result.update(
            {
                "batches": len(insert_lat),
                "inserted": inserted,
                "wall_s": wall,
                "rows_per_s": inserted / wall if wall else 0.0,
                "insert_only_rows_per_s": inserted / insert_total if insert_total else 0.0,
                "batch_insert_ms": {
                    p: _percentile(insert_lat, q) * 1000
                    for p, q in (("p50", 50), ("p95", 95), ("p99", 99), ("max", 100))
                },
                "batch_dedup_ms": {
                    p: _percentile(dedup_lat, q) * 1000
                    for p, q in (("p50", 50), ("p95", 95), ("max", 100))
                },
            }
        )

        total, distinct, domains = client.query(
            f"SELECT count(), uniqExact(event_id), uniqExact(domain) FROM {table}"
        ).first_row
        result["distinct_domains"] = int(domains)

        # Member 2's query at volume, through the real public function.
        query_lat: list[float] = []
        with _threats_table(table):
            for _ in range(QUERY_REPEATS):
                t = time.perf_counter()
                top = threatfeed.get_pending_targets(5)
                query_lat.append(time.perf_counter() - t)
        result["query_ms"] = {
            "p50": statistics.median(query_lat) * 1000,
            "max": max(query_lat) * 1000,
        }
        result["top_targets"] = [(t["domain"], t["url_count"]) for t in top]

        # Dedup at volume: re-sending the first batch must add nothing.
        t = time.perf_counter()
        again, dup_count = ingest.drop_duplicates(client, data[:batch], table=table)
        result["redelivery_ms"] = (time.perf_counter() - t) * 1000
        after = client.query(f"SELECT count() FROM {table}").first_row[0]

        counts = [t["url_count"] for t in top]
        result["checks"] = {
            f"row count == {rows}": int(total) == rows,
            "every event_id unique": int(distinct) == rows,
            f"redelivered batch -> 0 new, {min(batch, rows)} duplicates": (
                not again and dup_count == min(batch, rows) and int(after) == rows
            ),
            "get_pending_targets ranked by url_count desc": (
                len(top) == min(5, int(domains)) and counts == sorted(counts, reverse=True)
            ),
        }
    finally:
        try:
            if created and keep:
                log.info("--keep: leaving %s in place", table)
            elif created:
                client.command(f"DROP TABLE IF EXISTS {table}")
        finally:
            client.close()

    result["kept"] = keep
    result["ok"] = all(result["checks"].values())
    return result


def print_report(r: dict[str, Any]) -> None:
    """Human-readable summary of `run_bench()` output."""
    ins, ded, q = r["batch_insert_ms"], r["batch_dedup_ms"], r["query_ms"]
    print("=" * 66)
    print("ClickHouse threat layer -- CAPACITY benchmark (synthetic rows)")
    print("=" * 66)
    print(f"server            ClickHouse {r['server_version']}, table {r['table']}")
    print(f"volume            {r['inserted']:,} rows in {r['batches']} batch(es) of "
          f"{r['batch']:,}  (seed {r['seed']}, {r['distinct_domains']:,} domains)")
    print(f"wall time         {r['wall_s']:.2f} s  (dedup lookup + insert, per batch)")
    print(f"THROUGHPUT        {r['rows_per_s']:,.0f} rows/s end-to-end  |  "
          f"{r['insert_only_rows_per_s']:,.0f} rows/s insert-only")
    print(f"batch insert      p50 {ins['p50']:.0f} ms  p95 {ins['p95']:.0f} ms  "
          f"p99 {ins['p99']:.0f} ms  max {ins['max']:.0f} ms")
    print(f"batch dedup       p50 {ded['p50']:.0f} ms  p95 {ded['p95']:.0f} ms  "
          f"max {ded['max']:.0f} ms")
    print(f"Member 2 query    get_pending_targets(5) p50 {q['p50']:.0f} ms  "
          f"max {q['max']:.0f} ms over {r['rows']:,} rows")
    print(f"redelivery        {r['batch']:,}-row duplicate batch rejected in "
          f"{r['redelivery_ms']:.0f} ms")
    print("top targets       " + ", ".join(f"{d} ({n})" for d, n in r["top_targets"][:3]))
    print("\nchecks")
    for label, ok in r["checks"].items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    print(f"\n{r['table']} {'kept' if r['kept'] else 'dropped'}; "
          "nothing written to incoming_threats or ingest_runs.")
    print("NOTE: this is the store's capacity, not the live feed rate -- see "
          "`threatfeed.py --stats`.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline ClickHouse capacity benchmark.")
    parser.add_argument("--rows", type=int, default=DEFAULT_ROWS)
    parser.add_argument("--batch", type=int, default=DEFAULT_BATCH)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--keep", action="store_true", help="do not drop the bench table")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)
    return cli(args.rows, args.batch, seed=args.seed, keep=args.keep, verbose=args.verbose)


def cli(rows: int, batch: int, *, seed: int, keep: bool, verbose: bool = False) -> int:
    """Shared entrypoint for `bench.py` and `ingest.py --bench`; returns an exit code."""
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    if not verbose:
        logging.getLogger("ingest").setLevel(logging.WARNING)
    ingest.load_environment()
    try:
        result = run_bench(rows, batch, seed=seed, keep=keep)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return ingest.EXIT_USAGE
    except Exception as exc:  # noqa: BLE001 -- CLI: report and exit
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return ingest.EXIT_RUNTIME
    print_report(result)
    return ingest.EXIT_OK if result["ok"] else ingest.EXIT_RUNTIME


if __name__ == "__main__":
    sys.exit(main())
