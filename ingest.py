#!/usr/bin/env python3
"""
Active Threat Takedown Orchestrator -- URLhaus -> ClickHouse ingest.

Fetches the most recent malware URLs from the URLhaus API, maps them onto our
`incoming_threats` schema, and bulk-inserts them into a local ClickHouse
instance so the takedown pipeline can pick them up.

Usage:
    python3 ingest.py                  # ingest the 50 most recent records
    python3 ingest.py --limit 10       # ingest fewer records
    python3 ingest.py --dry-run        # fetch + map only, do not touch the DB

Required environment (read from .env / clickhouse.env, or the process env):
    CLICKHOUSE_HOST       default: localhost
    CLICKHOUSE_PORT       default: 8123
    CLICKHOUSE_USER       default: default
    CLICKHOUSE_PASSWORD   default: (empty)
    URLHAUS_AUTH_KEY      required -- see https://auth.abuse.ch/
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Sequence

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
# URLhaus `date_added` values are UTC and formatted as "2024-01-15 12:34:56".
URLHAUS_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

TABLE_NAME = "incoming_threats"
COLUMN_NAMES = ["event_id", "target_url", "timestamp", "threat_type", "action_status"]
DEFAULT_ACTION_STATUS = "PENDING"
DEFAULT_LIMIT = 50

CREATE_TABLE_DDL = f"""
CREATE TABLE IF NOT EXISTS {TABLE_NAME}
(
    event_id      String,
    target_url    String,
    `timestamp`   DateTime,
    threat_type   String,
    action_status String
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
    """Open a connection to the local ClickHouse instance."""
    host = os.getenv("CLICKHOUSE_HOST", "localhost")
    port = int(os.getenv("CLICKHOUSE_PORT", "8123"))
    user = os.getenv("CLICKHOUSE_USER", "default")
    password = os.getenv("CLICKHOUSE_PASSWORD", "")

    log.info("Connecting to ClickHouse at %s:%s as user %r", host, port, user)
    client = clickhouse_connect.get_client(
        host=host,
        port=port,
        username=user,
        password=password,
    )
    log.info("Connected to ClickHouse server version %s", client.server_version)
    return client


def ensure_schema(client: clickhouse_connect.driver.client.Client) -> None:
    """Create `incoming_threats` if it does not already exist."""
    log.info("Ensuring table %s exists (MergeTree, ORDER BY timestamp)", TABLE_NAME)
    client.command(CREATE_TABLE_DDL)


# --------------------------------------------------------------------------- #
# Fetch + transform
# --------------------------------------------------------------------------- #


def parse_timestamp(raw: Any) -> datetime | None:
    """Parse a URLhaus timestamp into a UTC-aware datetime.

    Returns None when the value is missing or not in the expected format.
    An aware datetime is used deliberately: clickhouse-connect will convert it
    into the column's timezone instead of guessing that the value is local time.
    """
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        naive = datetime.strptime(raw.strip(), URLHAUS_TIME_FORMAT)
    except ValueError:
        return None
    return naive.replace(tzinfo=timezone.utc)


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


def map_records(records: Sequence[dict[str, Any]], limit: int) -> list[tuple[Any, ...]]:
    """Map the first `limit` URLhaus records onto the incoming_threats columns.

    Rows that cannot satisfy the schema (missing id/url, unparseable timestamp)
    are skipped with a warning rather than aborting the whole batch.
    """
    selected = list(records[:limit])
    rows: list[tuple[Any, ...]] = []
    skipped: list[str] = []

    for index, record in enumerate(selected):
        if not isinstance(record, dict):
            skipped.append(f"#{index}: not an object")
            continue

        event_id = str(record.get("id") or "").strip()
        target_url = str(record.get("url") or "").strip()
        threat_type = str(record.get("threat") or "unknown").strip() or "unknown"
        timestamp = parse_timestamp(record.get("date_added"))

        if not event_id or not target_url or timestamp is None:
            skipped.append(
                f"#{index}: id={record.get('id')!r} "
                f"url={record.get('url')!r} "
                f"date_added={record.get('date_added')!r}"
            )
            continue

        rows.append(
            (event_id, target_url, timestamp, threat_type, DEFAULT_ACTION_STATUS)
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


def insert_rows(
    client: clickhouse_connect.driver.client.Client, rows: Sequence[tuple[Any, ...]]
) -> int:
    """Bulk-insert mapped rows in a single client.insert() call."""
    if not rows:
        log.warning("No valid rows to insert -- skipping insert entirely")
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
        "--dry-run",
        action="store_true",
        help="fetch and map records, but do not create the table or insert",
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

    if args.limit < 1:
        log.error("--limit must be >= 1 (got %d)", args.limit)
        return 2

    load_environment()

    client = None
    try:
        records = fetch_recent_urls()
        rows = map_records(records, args.limit)

        if args.dry_run:
            log.info("Dry run: %d row(s) mapped, database untouched", len(rows))
            for row in rows[:5]:
                log.info("  %s", row)
            if len(rows) > 5:
                log.info("  ... and %d more", len(rows) - 5)
            return 0

        client = connect_clickhouse()
        ensure_schema(client)
        inserted = insert_rows(client, rows)
        report_table_state(client)
        log.info("Done: %d row(s) inserted", inserted)
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
