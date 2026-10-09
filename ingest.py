#!/usr/bin/env python3
"""
Active Threat Takedown Orchestrator -- URLhaus -> ClickHouse ingest (Member 1).

Polls the live URLhaus `/v1/urls/recent/` feed, maps each record onto the
`incoming_threats` schema

    event_id, target_url, domain, ip_address, timestamp, threat_type,
    takedown_status (default 'PENDING'), feed_source, first_seen

drops records whose `event_id` is already stored, and bulk-inserts the rest
into ClickHouse. Member 2 consumes the result through `threatfeed.py`.

Behaviour worth knowing:
  * `date_added` is accepted as "YYYY-MM-DD HH:MM:SS", the same with a
    trailing " UTC" (the live format), or ISO-8601 with a `T`; always UTC.
  * If the feed returned records that pass the filter but *none* of them map,
    the run exits 3 instead of pretending to succeed.
  * `ip_address` is filled only when URLhaus's `host` is an IP literal, unless
    `--resolve-dns` is given (best-effort, short timeout, never raises).

Usage:
    python3 ingest.py                         # one-shot: 50 most recent records
    python3 ingest.py --limit 10              # fewer records
    python3 ingest.py --threat-type phishing  # only rows whose threat == phishing
    python3 ingest.py --resolve-dns           # best-effort DNS for hostnames (off by default)
    python3 ingest.py --dry-run               # fetch + map only, do not touch the DB
    python3 ingest.py --reset-schema          # DROP + recreate the table, then ingest
    python3 ingest.py --interval 600          # keep polling every 600 s (minimum 300)
    python3 ingest.py --self-test             # timestamp-parser self-check, no network

Environment (read from .env / clickhouse.env, or the process env):
    CLICKHOUSE_HOST       default: localhost  (or a ClickHouse Cloud host)
    CLICKHOUSE_PORT       default: 8123, or 8443 when CLICKHOUSE_SECURE is on
    CLICKHOUSE_USER       default: default
    CLICKHOUSE_PASSWORD   default: (empty)
    CLICKHOUSE_SECURE     default: off; set to 1 for ClickHouse Cloud (HTTPS)
    THREATS_TABLE         default: incoming_threats (tests point this elsewhere)
    URLHAUS_AUTH_KEY      required -- see https://auth.abuse.ch/
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import re
import socket
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Sequence
from urllib.parse import urlsplit

import clickhouse_connect
import requests
from dotenv import load_dotenv

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

# The repo ships `clickhouse.env`; plain `.env` is also honoured (first match wins
# because load_dotenv does not override already-populated variables).
ENV_FILE_CANDIDATES: tuple[str, ...] = (".env", "clickhouse.env")

URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
URLHAUS_TIMEOUT_SECONDS = 30
# URLhaus `date_added` values are UTC. Live (measured 2026-10-09) they are
# "2026-10-09 18:55:15 UTC" with a trailing zone marker; older docs showed the
# bare form. ISO-8601 ("...T...") is accepted too. Both are tried.
URLHAUS_TIME_FORMATS: tuple[str, ...] = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
)

TABLE_NAME = "incoming_threats"  # default; override with THREATS_TABLE
TABLE_ENV_VAR = "THREATS_TABLE"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DNS_TIMEOUT_SECONDS = 2.0
MIN_POLL_INTERVAL_SECONDS = 300
# `first_seen` is deliberately absent: the DDL default `now()` fills it
# server-side so it measures ingestion time, not the client's clock.
COLUMN_NAMES = [
    "event_id",
    "target_url",
    "domain",
    "ip_address",
    "timestamp",
    "threat_type",
    "takedown_status",
    "feed_source",
]
EXPECTED_COLUMNS = frozenset(COLUMN_NAMES) | {"first_seen"}
DEFAULT_TAKEDOWN_STATUS = "PENDING"
DEFAULT_FEED_SOURCE = "urlhaus"
DEFAULT_LIMIT = 50
DEFAULT_THREAT_TYPE = "all"

CREATE_TABLE_TEMPLATE = """
CREATE TABLE IF NOT EXISTS {table}
(
    event_id        String,                                    -- URLhaus `id`, the dedup key
    target_url      String,                                    -- URLhaus `url`
    domain          String,                                    -- derived, see derive_domain()
    ip_address      String,                                    -- '' when unknown
    `timestamp`     DateTime,                                  -- URLhaus `date_added`, UTC
    threat_type     String,                                    -- URLhaus `threat`
    takedown_status String DEFAULT 'PENDING',
    feed_source     LowCardinality(String) DEFAULT 'urlhaus',
    first_seen      DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY `timestamp`
"""
CREATE_TABLE_DDL = CREATE_TABLE_TEMPLATE.format(table=TABLE_NAME)

log = logging.getLogger("ingest")


# --------------------------------------------------------------------------- #
# Configuration / connection
# --------------------------------------------------------------------------- #


def table_name(explicit: str | None = None) -> str:
    """Return the threats table to use: `explicit`, else $THREATS_TABLE, else default.

    Table names cannot be bound as query parameters in DDL, so the name is
    validated as a plain identifier before it is ever placed into SQL.
    """
    name = (explicit or os.getenv(TABLE_ENV_VAR, "") or TABLE_NAME).strip()
    if not _IDENTIFIER_RE.match(name):
        raise RuntimeError(
            f"Invalid table name {name!r}: only letters, digits and '_' are allowed"
        )
    return name


def load_environment() -> None:
    """Populate os.environ from the available dotenv files.

    Looks in the current directory first, then next to this file, so that
    `threatfeed` works when imported from another working directory.
    """
    loaded: list[str] = []
    here = os.path.dirname(os.path.abspath(__file__))
    for directory in dict.fromkeys((os.getcwd(), here)):
        for name in ENV_FILE_CANDIDATES:
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate):
                load_dotenv(candidate, override=False)
                loaded.append(os.path.relpath(candidate))

    if loaded:
        log.info("Loaded environment from: %s", ", ".join(loaded))
    else:
        log.warning(
            "No env file found (looked for %s); relying on process environment",
            ", ".join(ENV_FILE_CANDIDATES),
        )


def connect_clickhouse() -> clickhouse_connect.driver.client.Client:
    """Open a ClickHouse connection from the environment.

    Nothing here is host-specific: point `CLICKHOUSE_HOST/PORT/USER/PASSWORD` at
    a local Docker container or at a ClickHouse Cloud service. Cloud speaks
    HTTPS, so set `CLICKHOUSE_SECURE=1` (and its port, usually 8443) for that.
    """
    host = os.getenv("CLICKHOUSE_HOST", "localhost")
    secure = os.getenv("CLICKHOUSE_SECURE", "").strip().lower() in ("1", "true", "yes", "on")
    port = int(os.getenv("CLICKHOUSE_PORT", "8443" if secure else "8123"))
    user = os.getenv("CLICKHOUSE_USER", "default")
    password = os.getenv("CLICKHOUSE_PASSWORD", "")

    log.info(
        "Connecting to ClickHouse at %s:%s as user %r (secure=%s)",
        host,
        port,
        user,
        secure,
    )
    client = clickhouse_connect.get_client(
        host=host,
        port=port,
        username=user,
        password=password,
        secure=secure,
    )
    log.info("Connected to ClickHouse server version %s", client.server_version)
    return client


def ensure_schema(
    client: clickhouse_connect.driver.client.Client,
    recreate: bool = False,
    *,
    table: str | None = None,
) -> None:
    """Create the threats table, optionally dropping a stale one first.

    `CREATE TABLE IF NOT EXISTS` can never repair a table with the old column
    set, so the repair path is an explicit `--reset-schema` (DROP + CREATE; the
    table only ever held test data). Without it a mismatched table is refused
    loudly rather than silently accepting inserts into the wrong shape.
    """
    table = table_name(table)
    if recreate:
        log.warning(
            "--reset-schema: dropping %s and recreating it (existing rows are lost)",
            table,
        )
        client.command(f"DROP TABLE IF EXISTS {table}")

    log.info("Ensuring table %s exists (MergeTree, ORDER BY timestamp)", table)
    client.command(CREATE_TABLE_TEMPLATE.format(table=table))
    assert_schema(client, table=table)


def assert_schema(
    client: clickhouse_connect.driver.client.Client, *, table: str | None = None
) -> None:
    """Fail loudly if the live table does not match the expected column set."""
    table = table_name(table)
    result = client.query(f"DESCRIBE TABLE {table}")
    actual = {row[0] for row in result.result_rows}
    missing = sorted(EXPECTED_COLUMNS - actual)
    unexpected = sorted(actual - EXPECTED_COLUMNS)
    if missing or unexpected:
        raise RuntimeError(
            f"{table} does not match the brief "
            f"(missing={missing}, unexpected={unexpected}). "
            "Re-run with --reset-schema to rebuild it."
        )


# --------------------------------------------------------------------------- #
# Fetch + transform
# --------------------------------------------------------------------------- #


def parse_timestamp(raw: Any) -> datetime | None:
    """Parse a URLhaus timestamp into a UTC-aware datetime.

    Tolerates the live "2026-10-09 18:55:15 UTC" form (trailing zone marker),
    the bare "2026-10-09 18:55:15" form, and ISO-8601 with a `T` separator
    (including a trailing `Z` or a numeric offset). Returns None when the value
    is missing or unparseable.

    An aware datetime is used deliberately: clickhouse-connect will convert it
    into the column's timezone instead of guessing that the value is local time.
    """
    if not isinstance(raw, str) or not raw.strip():
        return None

    value = raw.strip()
    if value.upper().endswith("UTC"):
        value = value[:-3].strip()
    if value[-1:] in ("Z", "z"):
        value = value[:-1].strip()
    if not value:
        return None

    for fmt in URLHAUS_TIME_FORMATS:
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def is_ip_literal(value: str) -> bool:
    """True when `value` is a bare IPv4/IPv6 literal (no port, no brackets)."""
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _host_of(value: str, *, is_url: bool = False) -> str:
    """Reduce a URL (`is_url=True`) or a bare `host[:port]` to a clean host.

    Lowercased, port stripped, trailing dot removed; IPv6 brackets dropped
    (e.g. '[::1]:80' -> '::1'). A URL is parsed strictly with
    `urlsplit(url).hostname`, so a scheme-less string yields ''. Returns ''
    when nothing host-like can be extracted (including hosts with whitespace).
    """
    value = value.strip()
    if not value:
        return ""
    candidate = value if is_url or "//" in value else f"//{value}"
    try:
        host = urlsplit(candidate).hostname or ""
    except ValueError:
        host = ""
    host = host.strip().lower().rstrip(".")
    if not host or any(ch.isspace() for ch in host):
        return ""
    return host


def derive_domain(host: Any, target_url: str) -> str:
    """Derive the grouping key `domain` (MEMBER1_PLAN.md 4.4).

    Prefers the API's `host`; falls back to `urlsplit(target_url).hostname`;
    lowercases; strips the port and a trailing dot; keeps an IP literal as its
    own value. Returns '' only when neither source yields a host -- callers
    must skip such a row, never store an empty domain.
    """
    domain = _host_of(host) if isinstance(host, str) else ""
    if not domain:
        domain = _host_of(target_url or "", is_url=True)
    return domain


_dns_pool: ThreadPoolExecutor | None = None


def _resolve_with_timeout(hostname: str, timeout: float = DNS_TIMEOUT_SECONDS) -> str:
    """Resolve `hostname` to an IPv4 string within `timeout` seconds, else ''.

    `socket.gethostbyname` has no timeout of its own, so it runs in a small
    worker pool and the caller stops waiting after `timeout`. Never raises.
    """
    global _dns_pool
    try:
        if _dns_pool is None:
            _dns_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dns")
        resolved = _dns_pool.submit(socket.gethostbyname, hostname).result(timeout=timeout)
    except Exception:  # noqa: BLE001 -- best-effort by design (D3)
        log.debug("DNS resolution failed or timed out for %r; storing ''", hostname)
        return ""
    return resolved if is_ip_literal(resolved) else ""


def derive_ip_address(host: Any, resolve_dns: bool = False) -> str:
    """Return the host as an IP literal, else '' (D3).

    Fills the column only when URLhaus's `host` is already an IP literal
    (`ipaddress.ip_address`). With `resolve_dns` enabled a hostname is
    resolved best-effort with a short timeout; any failure (blocked DNS,
    NXDOMAIN, timeout) yields ''. This never raises.
    """
    bare = _host_of(host) if isinstance(host, str) else ""
    if not bare:
        return ""
    if is_ip_literal(bare):
        return bare
    if resolve_dns:
        return _resolve_with_timeout(bare)
    return ""


def fetch_recent_urls() -> list[dict[str, Any]]:
    """Fetch the raw `urls` array from the URLhaus recent-URLs endpoint."""
    auth_key = os.getenv("URLHAUS_AUTH_KEY", "").strip()
    if not auth_key:
        raise RuntimeError(
            "URLHAUS_AUTH_KEY is not set. abuse.ch made API authentication "
            "mandatory on 2025-06-30, so this endpoint returns HTTP 401 without "
            "it. Request a free Auth-Key at https://auth.abuse.ch/ and add "
            "'URLHAUS_AUTH_KEY=<key>' to clickhouse.env."
        )

    log.info("Fetching %s", URLHAUS_RECENT_URL)
    try:
        response = requests.get(
            URLHAUS_RECENT_URL,
            headers={"Auth-Key": auth_key, "Accept": "application/json"},
            timeout=URLHAUS_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"URLhaus request failed: {exc}") from exc

    if response.status_code == 401:
        raise RuntimeError(
            "URLhaus returned 401 Unauthorized -- the Auth-Key header is missing "
            "or was stripped in transit."
        )
    if response.status_code == 403:
        raise RuntimeError(
            "URLhaus returned 403 -- the Auth-Key is not recognised "
            "(invalid, revoked, or not yet activated)."
        )
    if response.status_code == 429:
        raise RuntimeError(
            "URLhaus returned 429 Too Many Requests -- rate limit hit, retry later."
        )
    response.raise_for_status()

    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError(f"URLhaus returned non-JSON content: {exc}") from exc

    query_status = payload.get("query_status")
    if query_status not in (None, "ok"):
        raise RuntimeError(f"URLhaus API returned query_status={query_status!r}")

    records = payload.get("urls")
    if not isinstance(records, list):
        raise RuntimeError(
            "Unexpected URLhaus response shape: no 'urls' array present "
            f"(top-level keys: {sorted(payload)})"
        )

    log.info("URLhaus returned %d records", len(records))
    return records


def log_threat_breakdown(
    records: Sequence[dict[str, Any]], threat_type: str
) -> None:
    """Log the threat-type mix of the polled window (D2)."""
    counts = Counter(
        str(record.get("threat") or "unknown")
        for record in records
        if isinstance(record, dict)
    )
    if not counts:
        log.info("Threat-type breakdown: no records")
        return
    summary = ", ".join(f"{name}={n}" for name, n in counts.most_common())
    log.info("Threat-type breakdown of %d record(s): %s", len(records), summary)
    if threat_type != DEFAULT_THREAT_TYPE:
        log.info(
            "Filtering to threat_type=%r -> %d match(es)",
            threat_type,
            counts.get(threat_type, 0),
        )


def select_records(
    records: Sequence[dict[str, Any]],
    limit: int,
    threat_type: str = DEFAULT_THREAT_TYPE,
) -> list[Any]:
    """Apply the `threat_type` filter (D2), then take the first `limit` records."""
    filtered = [
        record
        for record in records
        if threat_type == DEFAULT_THREAT_TYPE
        or (
            isinstance(record, dict)
            and str(record.get("threat") or "").strip() == threat_type
        )
    ]
    return filtered[:limit]


def map_records(
    records: Sequence[dict[str, Any]],
    limit: int,
    *,
    threat_type: str = DEFAULT_THREAT_TYPE,
    resolve_dns: bool = False,
) -> list[tuple[Any, ...]]:
    """Map the first `limit` matching URLhaus records onto the table columns.

    `threat_type` filters the window before `limit` is applied (default 'all').
    Rows that cannot satisfy the schema (missing id/url, unparseable timestamp,
    no derivable domain) are skipped with a warning rather than aborting the
    whole batch; `main()` turns "everything skipped" into a non-zero exit.
    """
    selected = select_records(records, limit, threat_type)
    rows: list[tuple[Any, ...]] = []
    skipped: list[str] = []

    for index, record in enumerate(selected):
        if not isinstance(record, dict):
            skipped.append(f"#{index}: not an object")
            continue

        event_id = str(record.get("id") or "").strip()
        target_url = str(record.get("url") or "").strip()
        threat = str(record.get("threat") or "unknown").strip() or "unknown"
        timestamp = parse_timestamp(record.get("date_added"))
        host = record.get("host")

        if not event_id or not target_url or timestamp is None:
            skipped.append(
                f"#{index}: id={record.get('id')!r} "
                f"url={record.get('url')!r} "
                f"date_added={record.get('date_added')!r}"
            )
            continue

        domain = derive_domain(host, target_url)
        if not domain:
            skipped.append(
                f"#{index}: id={event_id!r} no domain derivable from "
                f"host={host!r} url={target_url!r}"
            )
            continue

        rows.append(
            (
                event_id,
                target_url,
                domain,
                derive_ip_address(host, resolve_dns),
                timestamp,
                threat,
                DEFAULT_TAKEDOWN_STATUS,
                DEFAULT_FEED_SOURCE,
            )
        )

    if skipped:
        log.warning("Skipped %d malformed record(s):", len(skipped))
        for detail in skipped:
            log.warning("  %s", detail)

    log.info("Mapped %d/%d records for insertion", len(rows), len(selected))
    return rows


# --------------------------------------------------------------------------- #
# Insert + verify
# --------------------------------------------------------------------------- #


def drop_duplicates(
    client: clickhouse_connect.driver.client.Client,
    rows: Sequence[tuple[Any, ...]],
    *,
    table: str | None = None,
) -> tuple[list[tuple[Any, ...]], int]:
    """Remove rows whose `event_id` is already in the table (4.3).

    `urls/recent/` is a sliding window, so re-polling re-presents overlapping
    URLs. Also collapses repeats inside the batch itself. The lookup is a
    parameterized query. Returns (fresh_rows, duplicate_count).
    """
    if not rows:
        return list(rows), 0

    table = table_name(table)
    event_ids = sorted({str(row[0]) for row in rows})
    result = client.query(
        f"SELECT DISTINCT event_id FROM {table} WHERE event_id IN {{ids:Array(String)}}",
        parameters={"ids": event_ids},
    )
    existing = {row[0] for row in result.result_rows}

    fresh: list[tuple[Any, ...]] = []
    seen: set[str] = set(existing)
    for row in rows:
        key = str(row[0])
        if key in seen:
            continue
        seen.add(key)
        fresh.append(row)
    return fresh, len(rows) - len(fresh)


def insert_rows(
    client: clickhouse_connect.driver.client.Client,
    rows: Sequence[tuple[Any, ...]],
    *,
    table: str | None = None,
) -> int:
    """Bulk-insert mapped rows in a single client.insert() call."""
    if not rows:
        log.info("No new rows to insert -- skipping insert entirely")
        return 0

    table = table_name(table)
    log.info(
        "Bulk-inserting %d rows into %s with columns %s",
        len(rows),
        table,
        ", ".join(COLUMN_NAMES),
    )
    client.insert(table, list(rows), column_names=COLUMN_NAMES)
    log.info("Insert completed")
    return len(rows)


def report_table_state(
    client: clickhouse_connect.driver.client.Client, *, table: str | None = None
) -> int:
    """Log the resulting row count so the run can be verified at a glance."""
    table = table_name(table)
    result = client.query(
        f"SELECT count(), countIf(takedown_status = 'PENDING'), max(`timestamp`) FROM {table}"
    )
    total, pending, newest = result.first_row
    log.info(
        "Verification: %s holds %s row(s), %s PENDING; newest timestamp = %s",
        table,
        total,
        pending,
        newest,
    )
    return int(total)


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #


def run_self_test() -> int:
    """Minimal timestamp-parser self-check covering both documented formats.

    A committed `tests/smoke_test.py` is Phase 2's job; this keeps the parser
    regression-checkable without network access or extra dependencies.
    """
    cases: tuple[tuple[str, datetime], ...] = (
        ("2026-10-09 18:55:15", datetime(2026, 10, 9, 18, 55, 15, tzinfo=timezone.utc)),
        ("2026-10-09 18:55:15 UTC", datetime(2026, 10, 9, 18, 55, 15, tzinfo=timezone.utc)),
        ("2026-10-09T18:55:15Z", datetime(2026, 10, 9, 18, 55, 15, tzinfo=timezone.utc)),
        ("2026-10-09T18:55:15+00:00", datetime(2026, 10, 9, 18, 55, 15, tzinfo=timezone.utc)),
    )
    failures = 0
    for raw, expected in cases:
        got = parse_timestamp(raw)
        ok = got == expected and got is not None and got.tzinfo is not None
        print(f"[{'PASS' if ok else 'FAIL'}] parse_timestamp({raw!r}) -> {got!r}")
        failures += 0 if ok else 1

    for raw in ("", "   ", None, "not-a-timestamp"):
        got = parse_timestamp(raw)
        ok = got is None
        print(f"[{'PASS' if ok else 'FAIL'}] parse_timestamp({raw!r}) -> None")
        failures += 0 if ok else 1

    print(f"self-test: {len(cases) + 4 - failures}/{len(cases) + 4} checks passed")
    return 1 if failures else 0


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ingest recent URLhaus malware URLs into ClickHouse."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help=f"maximum records to take from the URLhaus array (default: {DEFAULT_LIMIT})",
    )
    parser.add_argument(
        "--threat-type",
        default=DEFAULT_THREAT_TYPE,
        help=(
            "only ingest records with this URLhaus `threat` "
            f"(default: {DEFAULT_THREAT_TYPE}; e.g. 'phishing')"
        ),
    )
    parser.add_argument(
        "--resolve-dns",
        action="store_true",
        help=(
            "best-effort DNS resolution for hostname `host`s (off by default; "
            "never raises and keeps the ingest path independent of DNS)"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="fetch and map records, but do not create the table or insert",
    )
    parser.add_argument(
        "--reset-schema",
        "--recreate",
        dest="reset_schema",
        action="store_true",
        help=(
            "DROP and recreate the table before inserting (destroys existing rows); "
            "needed once to replace a table with an outdated column set"
        ),
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=0,
        metavar="SECONDS",
        help=(
            "keep polling every SECONDS (default: off = one-shot; minimum "
            f"{MIN_POLL_INTERVAL_SECONDS} to respect URLhaus rate limits)"
        ),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the timestamp-parser self-check and exit (no network, no DB)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="enable debug logging"
    )
    return parser.parse_args(argv)


EXIT_OK = 0
EXIT_RUNTIME = 1
EXIT_USAGE = 2
EXIT_NOTHING_MAPPED = 3


def run_once(args: argparse.Namespace, *, reset_schema: bool) -> int:
    """One poll: fetch -> map -> dedup -> insert. Returns a process exit code."""
    client = None
    try:
        records = fetch_recent_urls()
        log_threat_breakdown(records, args.threat_type)
        candidates = select_records(records, args.limit, args.threat_type)
        rows = map_records(
            records,
            args.limit,
            threat_type=args.threat_type,
            resolve_dns=args.resolve_dns,
        )

        if candidates and not rows:
            log.error(
                "Mapped 0/%d records although the feed returned %d record(s) "
                "matching threat_type=%r -- every record failed validation. "
                "This is the signature of a `date_added` format mismatch; "
                "refusing to report success.",
                len(candidates),
                len(records),
                args.threat_type,
            )
            return EXIT_NOTHING_MAPPED
        if not candidates:
            log.warning(
                "No records match threat_type=%r in this poll (feed returned %d); "
                "nothing to ingest",
                args.threat_type,
                len(records),
            )

        if args.dry_run:
            log.info("Dry run: %d row(s) mapped, database untouched", len(rows))
            for row in rows[:5]:
                log.info("  %s", row)
            if len(rows) > 5:
                log.info("  ... and %d more", len(rows) - 5)
            return EXIT_OK

        client = connect_clickhouse()
        ensure_schema(client, recreate=reset_schema)
        fresh, duplicates = drop_duplicates(client, rows)
        log.info("Dedup: %d new, %d duplicates skipped", len(fresh), duplicates)
        inserted = insert_rows(client, fresh)
        report_table_state(client)
        log.info(
            "Done: %d row(s) inserted, %d duplicate(s) skipped", inserted, duplicates
        )
        return EXIT_OK

    except RuntimeError as exc:
        log.error("%s", exc)
        return EXIT_RUNTIME
    except Exception:
        log.exception("Unexpected failure during ingest")
        return EXIT_RUNTIME
    finally:
        if client is not None:
            client.close()
            log.debug("ClickHouse connection closed")


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    if args.self_test:
        return run_self_test()

    if args.limit < 1:
        log.error("--limit must be >= 1 (got %d)", args.limit)
        return EXIT_USAGE
    if not str(args.threat_type).strip():
        log.error("--threat-type must not be empty (use 'all' to disable filtering)")
        return EXIT_USAGE
    if args.interval and args.interval < MIN_POLL_INTERVAL_SECONDS:
        log.error(
            "--interval must be >= %d seconds to respect URLhaus rate limits (got %d)",
            MIN_POLL_INTERVAL_SECONDS,
            args.interval,
        )
        return EXIT_USAGE
    if args.interval and args.dry_run:
        log.error("--interval and --dry-run cannot be combined")
        return EXIT_USAGE

    load_environment()
    try:
        table_name()
    except RuntimeError as exc:
        log.error("%s", exc)
        return EXIT_USAGE

    if not args.interval:
        return run_once(args, reset_schema=args.reset_schema)

    # Polling mode: transient failures (HTTP 429, network) are logged and the
    # loop continues; a parser regression (exit 3) stops it loudly.
    log.info("Polling every %d s (Ctrl-C to stop)", args.interval)
    reset = args.reset_schema
    try:
        while True:
            code = run_once(args, reset_schema=reset)
            reset = False  # never drop the table more than once
            if code == EXIT_NOTHING_MAPPED:
                return code
            if code != EXIT_OK:
                log.warning("Poll failed (exit %d); retrying next interval", code)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        log.info("Polling stopped by user")
        return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
