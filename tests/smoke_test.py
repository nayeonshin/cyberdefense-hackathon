#!/usr/bin/env python3
"""Smoke test for Member 1: ingest transforms + ClickHouse schema + threatfeed.

    .venv/bin/python tests/smoke_test.py

Never touches live data: everything runs against an isolated table
(`incoming_threats_test`, selected via THREATS_TABLE) that is created at the
start and dropped at the end. Needs a reachable ClickHouse (clickhouse.env),
but no URLhaus Auth-Key and no network beyond ClickHouse.

Exits 0 and prints "ALL CHECKS PASSED" only when every check passes.
Also importable by pytest (`test_smoke`), without adding a dependency.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
TEST_TABLE = "incoming_threats_test_" + uuid.uuid4().hex
TEST_RUNS_TABLE = "ingest_runs_test_" + uuid.uuid4().hex

import ingest  # noqa: E402
import threatfeed  # noqa: E402

BRIEF_COLUMNS = {
    "timestamp": "DateTime",
    "target_url": "String",
    "domain": "String",
    "ip_address": "String",
    "threat_type": "String",
    "takedown_status": "String",
}

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


def expect_value_error(label: str, fn, *args, **kwargs) -> None:
    try:
        fn(*args, **kwargs)
    except ValueError:
        check(True, f"{label} raises ValueError")
    except Exception as exc:  # noqa: BLE001
        check(False, f"{label} raised {type(exc).__name__} instead of ValueError")
    else:
        check(False, f"{label} did not raise")


def utc(*parts: int) -> datetime:
    return datetime(*parts, tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# 1. Pure unit checks (no DB)
# --------------------------------------------------------------------------- #


def unit_checks() -> None:
    print("\n1. parse_timestamp")
    want = utc(2026, 10, 9, 18, 55, 15)
    for raw in (
        "2026-10-09 18:55:15",
        "2026-10-09 18:55:15 UTC",
        "2026-10-09T18:55:15",
        "2026-10-09T18:55:15Z",
        "2026-10-09T18:55:15+00:00",
        "2026-10-09T20:55:15+02:00",
    ):
        got = ingest.parse_timestamp(raw)
        check(
            got == want and got is not None and got.utcoffset() == timezone.utc.utcoffset(None),
            f"parse_timestamp({raw!r}) == {want.isoformat()} and UTC-aware",
        )
    for raw in (None, "", "   ", "not-a-timestamp", "2026-13-45 99:99:99", 12345):
        check(ingest.parse_timestamp(raw) is None, f"parse_timestamp({raw!r}) is None")

    print("\n2. derive_domain / derive_ip_address")
    check(ingest.derive_domain("Evil.Example:8080", "http://x/") == "evil.example",
          "host with port + uppercase -> 'evil.example'")
    check(ingest.derive_domain("evil.example.", "http://x/") == "evil.example",
          "trailing dot stripped")
    check(ingest.derive_domain("1.2.3.4", "http://1.2.3.4:81/a") == "1.2.3.4",
          "IP literal host kept as domain")
    check(ingest.derive_domain(None, "HTTP://Bad.Example:443/x.exe") == "bad.example",
          "missing host falls back to URL hostname")
    check(ingest.derive_domain("", "http://[2001:DB8::1]:80/a") == "2001:db8::1",
          "IPv6 URL fallback, brackets and port stripped")
    check(ingest.derive_domain(None, "not a url") == "",
          "nothing derivable -> '' (caller skips)")
    check(ingest.derive_ip_address("1.2.3.4") == "1.2.3.4", "IP literal host -> ip_address")
    check(ingest.derive_ip_address("1.2.3.4:8080") == "1.2.3.4", "IP literal with port -> ip")
    check(ingest.derive_ip_address("evil.example") == "", "hostname without --resolve-dns -> ''")
    check(ingest.derive_ip_address(None) == "", "missing host -> ''")
    check(ingest.derive_ip_address("no-such-host.invalid", resolve_dns=True) == "",
          "--resolve-dns failure -> '' without raising")

    print("\n3. map_records + fail-loud")
    sample = [
        {"id": "1", "url": "http://a.example/x", "host": "a.example",
         "date_added": "2026-10-09 18:00:00 UTC", "threat": "malware_download"},
        {"id": "2", "url": "http://b.example/y", "host": "b.example",
         "date_added": "garbage", "threat": "phishing"},
        {"id": "3", "url": "http://c.example/z",
         "date_added": "2026-10-09 18:01:00 UTC", "threat": "phishing"},
    ]
    rows = ingest.map_records(sample, 50)
    check(len(rows) == 2, "bad timestamp row skipped, others mapped (2/3)")
    check(rows[1][2] == "c.example", "missing host -> domain from URL")
    check(len(ingest.map_records(sample, 1)) == 1, "--limit honoured")
    no_domain = [{"id": "9", "url": "not a url", "host": "",
                  "date_added": "2026-10-09 18:00:00 UTC", "threat": "x"}]
    check(ingest.map_records(no_domain, 50) == [], "row with no derivable domain skipped")
    phish = ingest.map_records(sample, 50, threat_type="phishing")
    check([r[0] for r in phish] == ["3"], "--threat-type phishing filters before mapping")

    # A run where every record fails validation must exit non-zero.
    original = ingest.fetch_recent_urls
    ingest.fetch_recent_urls = lambda: [  # type: ignore[assignment]
        {"id": str(i), "url": f"http://x{i}.example/", "date_added": "bogus"} for i in range(5)
    ]
    try:
        code = ingest.main(["--dry-run"])
    finally:
        ingest.fetch_recent_urls = original  # type: ignore[assignment]
    check(code == ingest.EXIT_NOTHING_MAPPED, f"0/N mapped -> exit {code} (expected 3, not 0)")


# --------------------------------------------------------------------------- #
# 2. Database + interface checks against the isolated table
# --------------------------------------------------------------------------- #

SYNTHETIC = [
    # busy.example: 3 distinct URLs -> must rank first
    {"id": "t-1", "url": "http://busy.example/a.exe", "host": "busy.example",
     "date_added": "2026-10-09 10:00:00 UTC", "threat": "malware_download"},
    {"id": "t-2", "url": "http://busy.example/b.exe", "host": "BUSY.example:8080",
     "date_added": "2026-10-09 11:00:00 UTC", "threat": "malware_download"},
    {"id": "t-3", "url": "http://busy.example/c.exe", "host": "busy.example",
     "date_added": "2026-10-09 12:00:00 UTC", "threat": "phishing"},
    # 9.9.9.9 and newer.example: 1 URL each; newer.example is more recent -> ranks before 9.9.9.9
    {"id": "t-4", "url": "http://9.9.9.9:81/bin.sh", "host": "9.9.9.9",
     "date_added": "2026-10-09 13:00:00 UTC", "threat": "malware_download"},
    {"id": "t-5", "url": "https://newer.example/p", "host": None,
     "date_added": "2026-10-09 14:00:00 UTC", "threat": "phishing"},
    # two.example: 2 URLs -> ranks second
    {"id": "t-6", "url": "http://two.example/1", "host": "two.example",
     "date_added": "2026-10-09 09:00:00 UTC", "threat": "malware_download"},
    {"id": "t-7", "url": "http://two.example/2", "host": "two.example",
     "date_added": "2026-10-09 09:30:00 UTC", "threat": "malware_download"},
]
EXPECTED_ORDER = ["busy.example", "two.example", "newer.example", "9.9.9.9"]


def db_checks() -> None:
    ingest.load_environment()
    client = ingest.connect_clickhouse()
    try:
        print(f"\n4. schema (isolated table {TEST_TABLE})")
        check(ingest.table_name() == TEST_TABLE, f"THREATS_TABLE resolves to {TEST_TABLE}")
        ingest.ensure_schema(client, recreate=True)
        ingest.ensure_schema(client)  # idempotent
        types = dict(
            client.query(
                "SELECT name, type FROM system.columns "
                "WHERE database = currentDatabase() AND table = {t:String}",
                parameters={"t": TEST_TABLE},
            ).result_rows
        )
        for col, typ in BRIEF_COLUMNS.items():
            check(types.get(col) == typ, f"column {col} is {typ} (got {types.get(col)})")
        server_tz = client.query("SELECT timezone()").first_row[0]
        check(server_tz == "UTC", f"server timezone is UTC (got {server_tz})")

        print("\n5. insert + UTC round-trip")
        check(threatfeed.get_pending_targets(5) == [], "empty table -> get_pending_targets() == []")
        rows = ingest.map_records(SYNTHETIC, 50)
        check(len(rows) == len(SYNTHETIC), f"all {len(SYNTHETIC)} synthetic rows mapped")
        fresh, dups = ingest.drop_duplicates(client, rows)
        check((len(fresh), dups) == (len(SYNTHETIC), 0), "first insert: all new, 0 duplicates")
        ingest.insert_rows(client, fresh)
        epoch = client.query(
            f"SELECT toUnixTimestamp(`timestamp`) FROM {TEST_TABLE} WHERE event_id = 't-1'"
        ).first_row[0]
        want = int(utc(2026, 10, 9, 10, 0, 0).timestamp())
        check(epoch == want, f"stored epoch {epoch} == {want} (no timezone shift)")
        status = client.query(
            f"SELECT DISTINCT takedown_status FROM {TEST_TABLE}"
        ).result_rows
        check(status == [("PENDING",)], "takedown_status defaults to PENDING")

        print("\n6. dedup (A6)")
        before = client.query(f"SELECT count() FROM {TEST_TABLE}").first_row[0]
        fresh, dups = ingest.drop_duplicates(client, ingest.map_records(SYNTHETIC, 50))
        added = ingest.insert_rows(client, fresh)
        after = client.query(f"SELECT count() FROM {TEST_TABLE}").first_row[0]
        check(added == 0 and dups == len(SYNTHETIC), f"re-insert: 0 new, {dups} duplicates")
        check(after == before, f"row count unchanged ({before} -> {after})")
        doubled = ingest.map_records(SYNTHETIC[:1] * 2, 50)
        check(len(ingest.drop_duplicates(client, doubled)[0]) == 0,
              "in-batch repeat of an existing id dropped")

        print("\n7. get_pending_targets (A5)")
        targets = threatfeed.get_pending_targets(5)
        order = [t["domain"] for t in targets]
        check(order == EXPECTED_ORDER, f"order by url_count DESC, last_seen DESC: {order}")
        top = targets[0]
        check(
            set(top) >= {"domain", "url_count", "first_seen", "last_seen",
                         "target_urls", "threat_types", "ip_address"},
            "all contract keys + additive keys present",
        )
        check(isinstance(top["url_count"], int) and top["url_count"] == 3, "url_count is int 3")
        check(all(t["first_seen"].tzinfo is not None and t["last_seen"].tzinfo is not None
                  for t in targets), "first_seen/last_seen are UTC-aware")
        check(top["first_seen"] == utc(2026, 10, 9, 10) and top["last_seen"] == utc(2026, 10, 9, 12),
              "first_seen/last_seen values exact")
        check(top["target_urls"] == ["http://busy.example/c.exe", "http://busy.example/b.exe",
                                     "http://busy.example/a.exe"], "target_urls newest first")
        check(top["threat_types"] == ["malware_download", "phishing"], "threat_types distinct, sorted")
        ip_row = next(t for t in targets if t["domain"] == "9.9.9.9")
        check(ip_row["ip_address"] == "9.9.9.9" and top["ip_address"] == "",
              "ip_address filled for IP literal, '' otherwise")
        check(len(threatfeed.get_pending_targets(2)) == 2, "limit honoured")
        check(threatfeed.get_pending_targets(5) == targets, "read-only: repeat call identical")
        for bad in (0, -1, "5", 2.0, True):
            expect_value_error(f"get_pending_targets({bad!r})", threatfeed.get_pending_targets, bad)

        print("\n8. update_takedown_status (A7, mutations_sync)")
        n = threatfeed.update_takedown_status("TAKEN_DOWN", domain="busy.example")
        check(n == 3, f"domain update matched 3 rows (got {n})")
        remaining = [t["domain"] for t in threatfeed.get_pending_targets(5)]
        check("busy.example" not in remaining,
              f"busy.example gone from pending IMMEDIATELY after update: {remaining}")
        n = threatfeed.update_takedown_status("SCANNED", event_id="t-6")
        two = next((t for t in threatfeed.get_pending_targets(5) if t["domain"] == "two.example"), None)
        check(n == 1 and two is not None and two["url_count"] == 1,
              "event_id update hits one row; domain stays pending with 1 URL")
        check(threatfeed.update_takedown_status("SCANNED", domain="nope.example") == 0,
              "no match -> 0")
        injection = "x' OR 1=1 --"
        check(threatfeed.update_takedown_status("SCANNED", domain=injection) == 0,
              "quote-laden domain is bound as data (0 rows, no injection)")
        pending_left = client.query(
            f"SELECT count() FROM {TEST_TABLE} WHERE takedown_status = 'PENDING'"
        ).first_row[0]
        check(pending_left == 3, f"exactly 3 rows still PENDING (got {pending_left})")
        expect_value_error("bad status", threatfeed.update_takedown_status,
                           "DONE", domain="two.example")
        expect_value_error("no selector", threatfeed.update_takedown_status, "SCANNED")
        expect_value_error("both selectors", threatfeed.update_takedown_status,
                           "SCANNED", domain="two.example", event_id="t-7")
        expect_value_error("empty domain", threatfeed.update_takedown_status,
                           "SCANNED", domain="")

        print(f"\n9. ingest_runs telemetry + get_feed_stats (isolated table {TEST_RUNS_TABLE})")
        client.command(f"DROP TABLE IF EXISTS {TEST_RUNS_TABLE}")
        check(ingest.runs_table_name() == TEST_RUNS_TABLE, f"RUNS_TABLE resolves to {TEST_RUNS_TABLE}")
        check(threatfeed.get_feed_stats()["recent_runs"] == [],
              "no runs table yet -> recent_runs == []")
        ingest.record_run_stats(client, {
            "urlhaus": {"fetched": 20, "mapped": 19, "new": 7, "duplicates": 12,
                        "error": "", "duration_ms": 123},
            "threatfox": {"fetched": 0, "mapped": 0, "new": 0, "duplicates": 0,
                          "error": "boom", "duration_ms": 45},
        })
        cols = [r[0] for r in client.query(f"DESCRIBE TABLE {TEST_RUNS_TABLE}").result_rows]
        check(cols == ingest.RUN_COLUMN_NAMES, f"ingest_runs columns as specified: {cols}")
        check(client.query(f"SELECT count() FROM {TEST_RUNS_TABLE}").first_row[0] == 2,
              "2 run rows written")
        stats = threatfeed.get_feed_stats()
        check(set(stats) == {"by_feed", "by_threat_type", "by_status", "recent_runs"},
              "get_feed_stats keys")
        check(sum(r["rows"] for r in stats["by_feed"]) == len(SYNTHETIC), "by_feed rows total")
        check({r["takedown_status"]: r["rows"] for r in stats["by_status"]}
              == {"TAKEN_DOWN": 3, "SCANNED": 1, "PENDING": 3}, f"by_status: {stats['by_status']}")
        check({r["threat_type"]: r["rows"] for r in stats["by_threat_type"]}
              == {"malware_download": 5, "phishing": 2}, "by_threat_type counts")
        runs = {r["feed_source"]: r for r in stats["recent_runs"]}
        check(runs["urlhaus"]["inserted"] == 7 and runs["urlhaus"]["duplicates"] == 12
              and runs["threatfox"]["error"] == "boom" and runs["urlhaus"]["duration_ms"] == 123,
              "recent_runs values round-trip")
        check(len(threatfeed.get_feed_stats(1)["recent_runs"]) == 1, "recent limit honoured")
        expect_value_error("get_feed_stats(0)", threatfeed.get_feed_stats, 0)
        # A broken stats write must warn, never raise.
        class _Broken:
            def command(self, *a, **k): raise RuntimeError("down")
        try:
            ingest.record_run_stats(_Broken(), {"urlhaus": {"fetched": 0, "mapped": 0, "new": 0,
                                                            "duplicates": 0, "error": ""}})
            check(True, "record_run_stats swallows write failures")
        except Exception as exc:  # noqa: BLE001
            check(False, f"record_run_stats raised {exc!r}")
    finally:
        client.command(f"DROP TABLE IF EXISTS {TEST_RUNS_TABLE}")
        client.command(f"DROP TABLE IF EXISTS {TEST_TABLE}")
        print(f"\n(dropped {TEST_TABLE}, {TEST_RUNS_TABLE})")
        client.close()


def _run() -> int:
    unit_checks()
    try:
        db_checks()
    except Exception as exc:  # noqa: BLE001 -- surface as a failed check
        failures.append(f"database section aborted: {type(exc).__name__}: {exc}")
        print(f"  [FAIL] database section aborted: {type(exc).__name__}: {exc}")

    print()
    print("=" * 60)
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED ({passes} passed):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"ALL CHECKS PASSED ({passes} checks)")
    return 0


def run() -> int:
    global passes
    passes = 0
    failures.clear()
    previous = os.environ.get("THREATS_TABLE")
    previous_runs = os.environ.get("RUNS_TABLE")
    os.environ["THREATS_TABLE"] = TEST_TABLE
    os.environ["RUNS_TABLE"] = TEST_RUNS_TABLE
    try:
        return _run()
    finally:
        if previous is None:
            os.environ.pop("THREATS_TABLE", None)
        else:
            os.environ["THREATS_TABLE"] = previous
        if previous_runs is None:
            os.environ.pop("RUNS_TABLE", None)
        else:
            os.environ["RUNS_TABLE"] = previous_runs


def test_smoke() -> None:  # pytest entrypoint
    if os.getenv("RUN_CLICKHOUSE_TESTS") != "1":
        import pytest
        pytest.skip("set RUN_CLICKHOUSE_TESTS=1 to use a local ClickHouse test server")
    assert run() == 0, failures


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-v", "--verbose", action="store_true", help="show ingest/threatfeed logs")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO if args.verbose else logging.CRITICAL)
    sys.exit(run())
