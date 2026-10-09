#!/usr/bin/env python3
"""
Active Threat Takedown Orchestrator -- URLhaus -> ClickHouse ingest.

Fetches the most recent malware URLs from the URLhaus API, maps them onto our
`incoming_threats` schema, and bulk-inserts them into a local ClickHouse
instance so the takedown pipeline can pick them up.

Usage:
    python3 ingest.py                      # ingest the 50 most recent records
    python3 ingest.py --limit 10           # ingest fewer records
    python3 ingest.py --threat-type phishing  # only rows whose threat == phishing
    python3 ingest.py --resolve-dns        # best-effort DNS for hostnames (slow, off by default)
    python3 ingest.py --dry-run            # fetch + map only, do not touch the DB
    python3 ingest.py --recreate           # DROP + recreate the table, then ingest
    python3 ingest.py --self-test          # run the timestamp-parser self-check, no network

Required environment (read from .env / clickhouse.env, or the process env):
    CLICKHOUSE_HOST       default: localhost  (or a ClickHouse Cloud host)
    CLICKHOUSE_PORT       default: 8123, or 8443 when CLICKHOUSE_SECURE is on
    CLICKHOUSE_USER       default: default
    CLICKHOUSE_PASSWORD   default: (empty)
    CLICKHOUSE_SECURE     default: off; set to 1 for ClickHouse Cloud (HTTPS)
    URLHAUS_AUTH_KEY      required -- see https://auth.abuse.ch/
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import socket
import sys
from collections import Counter
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

TABLE_NAME = "incoming_threats"
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

CREATE_TABLE_DDL = f"""
CREATE TABLE IF NOT EXISTS {TABLE_NAME}
(
    event_id        String,                                    -- URLhaus `id`, the dedup key
    target_url      String,                                    -- URLhaus `url`
    domain          String,                                    -- derived, see derive_domain()
    ip_address      String,                                    -- '' when unknown
    `timestamp`     DateTime,                                  -- URLhaus `date_added`, UTC
    threat_type     String,                                    -- URLhaus `threat`
    takedown_status String DEFAULT '{DEFAULT_TAKEDOWN_STATUS}',
    feed_source     LowCardinality(String) DEFAULT '{DEFAULT_FEED_SOURCE}',
    first_seen      DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY `timestamp`
"""

log = logging.getLogger("ingest")


# --------------------------------------------------------------------------- #
# Configuration / connection
# --------------------------------------------------------------------------- #


def load_environment() -> None:
    """Populate os.environ from the first available dotenv file."""
    loaded: list[str] = []
    for candidate in ENV_FILE_CANDIDATES:
        if os.path.isfile(candidate):
            load_dotenv(candidate, override=False)
            loaded.append(candidate)

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
    client: clickhouse_connect.driver.client.Client, recreate: bool = False
) -> None:
    """Create `incoming_threats`, optionally dropping a stale table first.

    The brief's column set differs from the table that shipped with the repo, so
    the intended path is a one-off `--recreate` (DROP + CREATE), not a migration.
    Without `--recreate` a mismatched table is refused loudly rather than
    silently accepting inserts into the wrong shape.
    """
    if recreate:
        log.warning(
            "--recreate: dropping %s and recreating it (existing rows are lost)",
            TABLE_NAME,
        )
        client.command(f"DROP TABLE IF EXISTS {TABLE_NAME}")

    log.info("Ensuring table %s exists (MergeTree, ORDER BY timestamp)", TABLE_NAME)
    client.command(CREATE_TABLE_DDL)
    assert_schema(client)


def assert_schema(client: clickhouse_connect.driver.client.Client) -> None:
    """Fail loudly if the live table does not match the expected column set."""
    result = client.query(f"DESCRIBE TABLE {TABLE_NAME}")
    actual = {row[0] for row in result.result_rows}
    missing = sorted(EXPECTED_COLUMNS - actual)
    unexpected = sorted(actual - EXPECTED_COLUMNS)
    if missing or unexpected:
        raise RuntimeError(
            f"{TABLE_NAME} does not match the brief "
            f"(missing={missing}, unexpected={unexpected}). "
            "Re-run with --recreate to rebuild it."
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


def _host_of(value: str) -> str:
    """Reduce a URL or bare `host[:port]` to a lowercased, port-stripped host.

    Returns '' when nothing host-like can be extracted. IPv6 literals keep their
    brackets stripped (e.g. '[::1]:80' -> '::1').
    """
    value = value.strip()
    if not value:
        return ""
    candidate = value if "//" in value else f"//{value}"
    try:
        host = urlsplit(candidate).hostname or ""
    except ValueError:
        host = ""
    return host.strip().lower()


def derive_domain(host: Any, target_url: str) -> str:
    """Derive the grouping key `domain` (MEMBER1_PLAN.md 4.4).

    Prefers the API's `host`; falls back to the hostname inside `target_url`;
    lowercases; strips the port; keeps an IP literal as its own value; never
    returns an empty string (last resort is the lowercased `target_url`).
    """
    for candidate in (host if isinstance(host, str) else "", target_url):
        domain = _host_of(candidate)
        if domain:
            return domain
    return (target_url or "").strip().lower()


def derive_ip_address(host: Any, resolve_dns: bool = False) -> str:
    """Return the host as an IP literal, else '' (D3).

    Fills the column only when URLhaus's `host` is already an IP literal. With
    `resolve_dns` enabled a hostname is resolved best-effort via
    `socket.gethostbyname`; any failure (blocked DNS, NXDOMAIN, timeout) yields
    ''. This never raises, so it can never break the ingest path.
    """
    bare = _host_of(host) if isinstance(host, str) else ""
    if not bare:
        return ""
    if is_ip_literal(bare):
        return bare
    if resolve_dns:
        try:
            return socket.gethostbyname(bare)
        except OSError:
            log.debug("DNS resolution failed for %r; storing ''", bare)
            return ""
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


def map_records(
    records: Sequence[dict[str, Any]],
    limit: int,
    *,
    threat_type: str = DEFAULT_THREAT_TYPE,
    resolve_dns: bool = False,
) -> list[tuple[Any, ...]]:
    """Map the first `limit` matching URLhaus records onto the table columns.

    `threat_type` filters the window before `limit` is applied (default 'all').
    Rows that cannot satisfy the schema (missing id/url, unparseable timestamp)
    are skipped with a warning rather than aborting the whole batch.
    """
    filtered = [
        record
        for record in records
        if threat_type == DEFAULT_THREAT_TYPE
        or str((record or {}).get("threat") or "").strip() == threat_type
    ]
    selected = filtered[:limit]
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

        rows.append(
            (
                event_id,
                target_url,
                derive_domain(host, target_url),
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
) -> tuple[list[tuple[Any, ...]], int]:
    """Remove rows whose `event_id` is already in the table (4.3).

    `urls/recent/` is a sliding window, so re-polling re-presents overlapping
    URLs. Returns (fresh_rows, duplicate_count).
    """
    if not rows:
        return list(rows), 0

    event_ids = [str(row[0]) for row in rows]
    result = client.query(
        f"SELECT event_id FROM {TABLE_NAME} WHERE event_id IN {{ids:Array(String)}}",
        parameters={"ids": event_ids},
    )
    existing = {row[0] for row in result.result_rows}
    if not existing:
        return list(rows), 0

    fresh = [row for row in rows if str(row[0]) not in existing]
    return fresh, len(rows) - len(fresh)


def insert_rows(
    client: clickhouse_connect.driver.client.Client, rows: Sequence[tuple[Any, ...]]
) -> int:
    """Bulk-insert mapped rows in a single client.insert() call."""
    if not rows:
        log.warning("No new rows to insert -- skipping insert entirely")
        return 0

    log.info(
        "Bulk-inserting %d rows into %s with columns %s",
        len(rows),
        TABLE_NAME,
        ", ".join(COLUMN_NAMES),
    )
    client.insert(TABLE_NAME, list(rows), column_names=COLUMN_NAMES)
    log.info("Insert completed")
    return len(rows)


def report_table_state(client: clickhouse_connect.driver.client.Client) -> None:
    """Log the resulting row count so the run can be verified at a glance."""
    result = client.query(
        f"SELECT count(), max(`timestamp`) FROM {TABLE_NAME}"
    )
    total, newest = result.first_row
    log.info("Verification: %s holds %s row(s); newest timestamp = %s", TABLE_NAME, total, newest)


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
        "--recreate",
        action="store_true",
        help="DROP and recreate the table before inserting (destroys existing rows)",
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
        return 2
    if not str(args.threat_type).strip():
        log.error("--threat-type must not be empty (use 'all' to disable filtering)")
        return 2

    load_environment()

    client = None
    try:
        records = fetch_recent_urls()
        log_threat_breakdown(records, args.threat_type)
        rows = map_records(
            records,
            args.limit,
            threat_type=args.threat_type,
            resolve_dns=args.resolve_dns,
        )

        if not rows and records and args.threat_type == DEFAULT_THREAT_TYPE:
            log.error(
                "Mapped 0/%d records although the feed returned data -- every "
                "record failed validation. This is the signature of a "
                "`date_added` format mismatch; refusing to report success.",
                len(records),
            )
            return 3

        if args.dry_run:
            log.info("Dry run: %d row(s) mapped, database untouched", len(rows))
            for row in rows[:5]:
                log.info("  %s", row)
            if len(rows) > 5:
                log.info("  ... and %d more", len(rows) - 5)
            return 0

        client = connect_clickhouse()
        ensure_schema(client, recreate=args.recreate)
        fresh, duplicates = drop_duplicates(client, rows)
        if duplicates:
            log.info(
                "Skipped %d duplicate row(s) already present in %s",
                duplicates,
                TABLE_NAME,
            )
        inserted = insert_rows(client, fresh)
        report_table_state(client)
        log.info(
            "Done: %d row(s) inserted, %d duplicate(s) skipped", inserted, duplicates
        )
        return 0

    except RuntimeError as exc:
        log.error("%s", exc)
        return 1
    except Exception:
        log.exception("Unexpected failure during ingest")
        return 1
    finally:
        if client is not None:
            client.close()
            log.debug("ClickHouse connection closed")


if __name__ == "__main__":
    sys.exit(main())
