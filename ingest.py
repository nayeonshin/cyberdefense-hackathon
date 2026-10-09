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
    python3 ingest.py --feeds all             # urlhaus + openphish (phishing) + threatfox (C2/IOCs)
    python3 ingest.py --feeds openphish,threatfox --limit 100   # --limit applies per feed
    python3 ingest.py --reset-schema          # DROP + recreate the table, then ingest
    python3 ingest.py --interval 600          # keep polling every 600 s (minimum 300)
    python3 ingest.py --daemon                # autonomous: all feeds, per-feed schedule + backoff
    python3 ingest.py --daemon --max-cycles 2 --interval 60   # bounded demo run
    python3 ingest.py --self-test             # parser + scheduler self-check, no network
    python3 ingest.py --bench                 # offline CAPACITY benchmark (synthetic rows,
                                              # isolated table; see bench.py)
    python3 ingest.py --bench --rows 1000000 --batch 50000

Environment (read from .env / clickhouse.env, or the process env):
    CLICKHOUSE_HOST       default: localhost  (or a ClickHouse Cloud host)
    CLICKHOUSE_PORT       default: 8123, or 8443 when CLICKHOUSE_SECURE is on
    CLICKHOUSE_USER       default: default
    CLICKHOUSE_PASSWORD   default: (empty)
    CLICKHOUSE_SECURE     default: off; set to 1 for ClickHouse Cloud (HTTPS)
    THREATS_TABLE         default: incoming_threats (tests point this elsewhere)
    RUNS_TABLE            default: ingest_runs -- per-feed run telemetry (tests point this elsewhere)
    URLHAUS_AUTH_KEY      required -- see https://auth.abuse.ch/
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import logging
import os
import re
import signal
import socket
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Sequence
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
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
FEED_TIMEOUT_SECONDS = 20
THREATFOX_IOC_TYPES = frozenset({"url", "domain", "ip:port"})
# ThreatFox `threat_type` -> normalized value; unknown values pass through lower-cased.
THREATFOX_THREAT_MAP = {"botnet_cc": "c2", "payload_delivery": "malware_download"}
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
DEDUP_LOOKUP_CHUNK = 2000  # event_ids per dedup IN-lookup, see drop_duplicates()
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

# Per-feed run telemetry. Deliberately a separate table: `incoming_threats`
# keeps the brief's schema untouched.
RUNS_TABLE_NAME = "ingest_runs"  # default; override with RUNS_TABLE
RUNS_TABLE_ENV_VAR = "RUNS_TABLE"
RUN_COLUMN_NAMES = [
    "run_ts",
    "feed_source",
    "fetched",
    "mapped",
    "inserted",
    "duplicates",
    "error",
    "duration_ms",
]
CREATE_RUNS_TABLE_TEMPLATE = """
CREATE TABLE IF NOT EXISTS {table}
(
    run_ts      DateTime,
    feed_source LowCardinality(String),
    fetched     UInt32,
    mapped      UInt32,
    inserted    UInt32,
    duplicates  UInt32,
    error       String,
    duration_ms UInt32
)
ENGINE = MergeTree
ORDER BY (feed_source, run_ts)
"""

# Daemon scheduling.
DAEMON_MIN_INTERVAL_SECONDS = 60  # floor for --interval in --daemon mode
BACKOFF_CAP_SECONDS = 3600  # a repeatedly failing feed is retried at most this rarely

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


def runs_table_name(explicit: str | None = None) -> str:
    """Return the run-telemetry table: `explicit`, else $RUNS_TABLE, else default."""
    name = (explicit or os.getenv(RUNS_TABLE_ENV_VAR, "") or RUNS_TABLE_NAME).strip()
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
# Feed adapters (registry: FEEDS)
# --------------------------------------------------------------------------- #


class NothingMappedError(RuntimeError):
    """A feed returned candidate records but none could be mapped (exit 3)."""


@dataclass(frozen=True)
class Feed:
    """One feed adapter: `fetch(limit)` -> raw items, `map(raw, args)` -> rows.

    Rows are tuples in COLUMN_NAMES order. `args` carries per-run options
    (`limit`, `threat_type`, `resolve_dns`); only URLhaus uses the latter two.
    `min_interval` is the shortest polling period (seconds) `--daemon` uses.
    """

    name: str
    fetch: Callable[[int], list[Any]]
    map: Callable[[list[Any], argparse.Namespace], list[tuple[Any, ...]]]
    min_interval: int = 600


def _abuse_ch_key() -> str:
    key = os.getenv("URLHAUS_AUTH_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "URLHAUS_AUTH_KEY is not set (the same abuse.ch Auth-Key is used for "
            "ThreatFox); get one at https://auth.abuse.ch/"
        )
    return key


# --- URLhaus: thin wrapper over the existing functions ---------------------- #


def _fetch_urlhaus(limit: int) -> list[Any]:
    return fetch_recent_urls()  # `limit` and the threat filter are applied in map


def _map_urlhaus(raw: list[Any], args: argparse.Namespace) -> list[tuple[Any, ...]]:
    log_threat_breakdown(raw, args.threat_type)
    candidates = select_records(raw, args.limit, args.threat_type)
    rows = map_records(
        raw, args.limit, threat_type=args.threat_type, resolve_dns=args.resolve_dns
    )
    if candidates and not rows:
        raise NothingMappedError(
            f"Mapped 0/{len(candidates)} records although the feed returned "
            f"{len(raw)} record(s) matching threat_type={args.threat_type!r} -- "
            "every record failed validation. This is the signature of a "
            "`date_added` format mismatch; refusing to report success."
        )
    if not candidates:
        log.warning(
            "No records match threat_type=%r in this poll (feed returned %d); "
            "nothing to ingest",
            args.threat_type,
            len(raw),
        )
    return rows


# --- OpenPhish --------------------------------------------------------------- #


def _fetch_openphish(limit: int) -> list[Any]:
    """Fetch the plain-text feed; returns [{'url', 'fetched_at'}] (first `limit`)."""
    log.info("Fetching %s", OPENPHISH_FEED_URL)
    try:
        response = requests.get(OPENPHISH_FEED_URL, timeout=FEED_TIMEOUT_SECONDS)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"OpenPhish request failed: {exc}") from exc
    fetched_at = datetime.now(timezone.utc).replace(microsecond=0)
    lines = [ln.strip() for ln in response.text.splitlines() if ln.strip()]
    log.info("OpenPhish returned %d line(s)", len(lines))
    return [{"url": ln, "fetched_at": fetched_at} for ln in lines[:limit]]


def map_openphish(raw: Sequence[Any]) -> list[tuple[Any, ...]]:
    """Map OpenPhish items onto rows; blank/invalid URLs are skipped.

    The feed carries no timestamp, so the fetch time (UTC) is used.
    event_id = 'openphish-' + first 24 hex chars of sha256('openphish|' + url).
    """
    rows: list[tuple[Any, ...]] = []
    skipped = 0
    for item in raw:
        url = str(item.get("url") or "").strip() if isinstance(item, dict) else ""
        fetched_at = item.get("fetched_at") if isinstance(item, dict) else None
        host = _host_of(url, is_url=True) if url else ""
        if (
            not host
            or not url.lower().startswith(("http://", "https://"))
            or not fetched_at
        ):
            skipped += 1
            continue
        digest = hashlib.sha256(f"openphish|{url}".encode("utf-8")).hexdigest()[:24]
        rows.append(
            (
                f"openphish-{digest}",
                url,
                host,
                host if is_ip_literal(host) else "",
                fetched_at,
                "phishing",
                DEFAULT_TAKEDOWN_STATUS,
                "openphish",
            )
        )
    if skipped:
        log.warning("OpenPhish: skipped %d blank/invalid line(s)", skipped)
    return rows


# --- ThreatFox --------------------------------------------------------------- #


def _fetch_threatfox(limit: int) -> list[Any]:
    """POST get_iocs(days=1); keep url/domain/ip:port IOCs, newest first, `limit`."""
    log.info("Fetching %s (get_iocs, days=1)", THREATFOX_API_URL)
    try:
        response = requests.post(
            THREATFOX_API_URL,
            json={"query": "get_iocs", "days": 1},
            headers={"Auth-Key": _abuse_ch_key()},
            timeout=FEED_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        raise RuntimeError(f"ThreatFox request failed: {exc}") from exc
    except ValueError as exc:
        raise RuntimeError(f"ThreatFox returned non-JSON content: {exc}") from exc

    if payload.get("query_status") != "ok" or not isinstance(payload.get("data"), list):
        raise RuntimeError(
            f"ThreatFox query_status={payload.get('query_status')!r}, "
            f"data={type(payload.get('data')).__name__}"
        )
    data = payload["data"]
    iocs = [
        d
        for d in data
        if isinstance(d, dict) and d.get("ioc_type") in THREATFOX_IOC_TYPES
    ]
    iocs.sort(key=lambda d: str(d.get("first_seen") or ""), reverse=True)
    log.info(
        "ThreatFox returned %d IOC(s); %d of type url/domain/ip:port",
        len(data),
        len(iocs),
    )
    return iocs[:limit]


def map_threatfox(raw: Sequence[Any]) -> list[tuple[Any, ...]]:
    """Map ThreatFox IOCs (url, domain, ip:port) onto rows; others are skipped."""
    rows: list[tuple[Any, ...]] = []
    skipped = 0
    families: Counter[str] = Counter()
    for ioc in raw:
        if not isinstance(ioc, dict):
            skipped += 1
            continue
        ioc_id = str(ioc.get("id") or "").strip()
        value = str(ioc.get("ioc") or "").strip()
        ioc_type = ioc.get("ioc_type")
        timestamp = parse_timestamp(ioc.get("first_seen"))
        if not ioc_id or not value or timestamp is None:
            skipped += 1
            continue

        if ioc_type == "url":
            target_url = value
            domain = _host_of(value, is_url=True)
            ip = domain if is_ip_literal(domain) else ""
        elif ioc_type == "domain":
            domain = _host_of(value)
            target_url = f"http://{domain}"
            ip = domain if is_ip_literal(domain) else ""
        elif ioc_type == "ip:port":
            host, _, port = value.rpartition(":")
            if not is_ip_literal(host) or not port.isdigit():
                skipped += 1
                continue
            domain, ip = host, host
            target_url = f"http://{host}:{port}"
        else:
            skipped += 1
            continue
        if not domain:
            skipped += 1
            continue

        raw_threat = str(ioc.get("threat_type") or "").strip().lower()
        threat = THREATFOX_THREAT_MAP.get(raw_threat, raw_threat or "unknown")
        families[str(ioc.get("malware_printable") or ioc.get("malware") or "unknown")] += 1
        rows.append(
            (
                f"threatfox-{ioc_id}",
                target_url,
                domain,
                ip,
                timestamp,
                threat,
                DEFAULT_TAKEDOWN_STATUS,
                "threatfox",
            )
        )
    if skipped:
        log.warning("ThreatFox: skipped %d unsupported/malformed IOC(s)", skipped)
    if families:
        log.info(
            "ThreatFox malware families: %s",
            ", ".join(f"{n}={c}" for n, c in families.most_common(8)),
        )
    return rows


FEEDS: dict[str, Feed] = {
    "urlhaus": Feed("urlhaus", _fetch_urlhaus, _map_urlhaus, min_interval=300),
    "openphish": Feed(
        "openphish", _fetch_openphish, lambda raw, _a: map_openphish(raw), min_interval=600
    ),
    "threatfox": Feed(
        "threatfox", _fetch_threatfox, lambda raw, _a: map_threatfox(raw), min_interval=600
    ),
}
DEFAULT_FEEDS = "urlhaus"


def parse_feed_names(spec: str) -> list[str]:
    """Turn a `--feeds` value ('all' or a comma list) into registry names."""
    names = [n.strip().lower() for n in spec.split(",") if n.strip()]
    if not names:
        raise ValueError("--feeds must not be empty")
    if "all" in names:
        return list(FEEDS)
    unknown = [n for n in names if n not in FEEDS]
    if unknown:
        raise ValueError(
            f"unknown feed(s) {unknown}; choose from {', '.join(FEEDS)} or 'all'"
        )
    return list(dict.fromkeys(names))


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
    # Chunked: the ids travel as one HTTP form field, and ClickHouse rejects
    # fields over `http_max_field_value_size` (128 KiB by default) -- about
    # 5-10k ids. Found by the --bench capacity run at 10k-row batches.
    existing: set[str] = set()
    for start in range(0, len(event_ids), DEDUP_LOOKUP_CHUNK):
        result = client.query(
            f"SELECT DISTINCT event_id FROM {table} WHERE event_id IN {{ids:Array(String)}}",
            parameters={"ids": event_ids[start : start + DEDUP_LOOKUP_CHUNK]},
        )
        existing.update(row[0] for row in result.result_rows)

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


def _feed_self_tests() -> tuple[int, int]:
    """Offline checks for the OpenPhish and ThreatFox mappers -> (failures, total)."""
    t = datetime(2026, 10, 9, 12, 0, 0, tzinfo=timezone.utc)
    checks: list[tuple[str, bool]] = []

    phish = map_openphish(
        [
            {"url": "https://Evil.Example.com/login?x=1", "fetched_at": t},
            {"url": "", "fetched_at": t},
            {"url": "not a url", "fetched_at": t},
            {"url": "http://1.2.3.4/a", "fetched_at": t},
        ]
    )
    checks.append(("openphish: blank/invalid skipped, 2 rows", len(phish) == 2))
    checks.append(
        (
            "openphish: hostname row",
            phish[0][1:] == (
                "https://Evil.Example.com/login?x=1",
                "evil.example.com",
                "",
                t,
                "phishing",
                "PENDING",
                "openphish",
            ),
        )
    )
    checks.append(("openphish: IP host fills ip_address", phish[1][2:4] == ("1.2.3.4", "1.2.3.4")))
    again = map_openphish([{"url": "http://1.2.3.4/a", "fetched_at": t}])
    checks.append(("openphish: event_id stable", again[0][0] == phish[1][0]))
    checks.append(("openphish: event_id format", phish[0][0].startswith("openphish-") and len(phish[0][0]) == 34))

    def ioc(i: str, value: str, kind: str, threat: str) -> dict[str, Any]:
        return {
            "id": i,
            "ioc": value,
            "ioc_type": kind,
            "threat_type": threat,
            "malware_printable": "Fam",
            "first_seen": "2026-10-09 19:45:48 UTC",
        }

    ts = datetime(2026, 10, 9, 19, 45, 48, tzinfo=timezone.utc)
    tf = map_threatfox(
        [
            ioc("1", "http://bad.example.org/x.exe", "url", "payload_delivery"),
            ioc("2", "c2.example.net", "domain", "botnet_cc"),
            ioc("3", "94.158.187.147:25204", "ip:port", "botnet_cc"),
            ioc("4", "d41d8cd98f00b204e9800998ecf8427e", "md5_hash", "payload"),
        ]
    )
    checks.append(("threatfox: hash IOC skipped, 3 rows", len(tf) == 3))
    checks.append(
        (
            "threatfox: url row",
            tf[0] == ("threatfox-1", "http://bad.example.org/x.exe", "bad.example.org", "", ts, "malware_download", "PENDING", "threatfox"),
        )
    )
    checks.append(
        (
            "threatfox: domain row + botnet_cc -> c2",
            tf[1] == ("threatfox-2", "http://c2.example.net", "c2.example.net", "", ts, "c2", "PENDING", "threatfox"),
        )
    )
    checks.append(
        (
            "threatfox: ip:port row",
            tf[2] == ("threatfox-3", "http://94.158.187.147:25204", "94.158.187.147", "94.158.187.147", ts, "c2", "PENDING", "threatfox"),
        )
    )
    checks.append(("threatfox: event_id stable", map_threatfox([ioc("1", "http://bad.example.org/x.exe", "url", "payload_delivery")])[0][0] == tf[0][0]))
    checks.append(("parse_feed_names: all/list/unknown", parse_feed_names("all") == list(FEEDS) and parse_feed_names("openphish, threatfox") == ["openphish", "threatfox"] and _raises(ValueError, parse_feed_names, "nope")))
    checks.extend(scheduler_self_tests())

    failures = 0
    for label, ok in checks:
        print(f"[{'PASS' if ok else 'FAIL'}] {label}")
        failures += 0 if ok else 1
    return failures, len(checks)


def scheduler_self_tests() -> list[tuple[str, bool]]:
    """Offline checks of `Scheduler` / `run_daemon` with an injectable clock."""
    now = [1000.0]
    clock = lambda: now[0]  # noqa: E731
    names = ["urlhaus", "openphish", "threatfox"]
    out: list[tuple[str, bool]] = []

    s = Scheduler(names, clock=clock)
    out.append(("scheduler: all feeds due at start", s.due() == names))
    out.append(
        (
            "scheduler: per-feed intervals 300/600/600",
            [s.interval(n) for n in names] == [300, 600, 600],
        )
    )
    for n in names:
        s.record(n, ok=True)
    out.append(("scheduler: nothing due right after a run", s.due() == []))
    out.append(("scheduler: sleeps until earliest feed (300 s)", s.seconds_until_next() == 300))
    now[0] += 300
    out.append(("scheduler: only urlhaus due after 300 s", s.due() == ["urlhaus"]))
    now[0] += 300
    out.append(("scheduler: all due after 600 s", s.due() == names))

    b = Scheduler(["urlhaus"], clock=clock)
    seen = []
    for _ in range(6):
        b.record("urlhaus", ok=False)
        seen.append(b.interval("urlhaus"))
    out.append(("backoff: doubles 600,1200,2400 then caps at 3600", seen == [600, 1200, 2400, 3600, 3600, 3600]))
    b.record("urlhaus", ok=True)
    out.append(("backoff: resets to base after success", b.interval("urlhaus") == 300))

    f = Scheduler(names, override=10, clock=clock)
    out.append(("interval floor: override 10 -> 60 s", [f.interval(n) for n in names] == [60, 60, 60]))
    o = Scheduler(names, override=900, clock=clock)
    out.append(("interval override applies to all feeds", [o.interval(n) for n in names] == [900, 900, 900]))

    # run_daemon end to end with a fake clock, runner and sleep.
    calls: list[list[str]] = []
    slept: list[float] = []

    def fake_sleep(sec: float) -> None:
        slept.append(sec)
        now[0] += sec

    def fake_runner(
        _args: argparse.Namespace, due: Sequence[str], *, reset_schema: bool
    ) -> tuple[int, dict[str, dict[str, Any]]]:
        calls.append(list(due))
        return 0, {n: {"error": "boom" if n == "threatfox" else ""} for n in due}

    ns = argparse.Namespace(feed_names=names, interval=0, max_cycles=3)
    code = run_daemon(
        ns,
        clock=clock,
        sleep=fake_sleep,
        runner=fake_runner,
        count_rows=lambda: 0,
        install_signals=False,
    )
    out.append(("daemon: exits 0 after --max-cycles", code == EXIT_OK and len(calls) == 3))
    out.append(("daemon: cycle 1 runs all, cycle 2 only urlhaus", calls[:2] == [names, ["urlhaus"]]))
    out.append(("daemon: cycle 3 runs urlhaus+openphish (threatfox backed off)", calls[2:] == [["urlhaus", "openphish"]]))
    return out


def _raises(exc: type[BaseException], fn: Callable[..., Any], *a: Any) -> bool:
    try:
        fn(*a)
    except exc:
        return True
    return False


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

    feed_failures, feed_total = _feed_self_tests()
    failures += feed_failures
    total = len(cases) + 4 + feed_total  # scheduler checks are part of feed_total
    print(f"self-test: {total - failures}/{total} checks passed")
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
        "--feeds",
        default=None,
        help=(
            "comma-separated feeds to ingest, or 'all' "
            f"(choices: {', '.join(FEEDS)}; default: {DEFAULT_FEEDS}, "
            "or 'all' with --daemon); --limit applies per feed"
        ),
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
            f"{MIN_POLL_INTERVAL_SECONDS} to respect URLhaus rate limits). With "
            f"--daemon it overrides every feed's own interval (minimum "
            f"{DAEMON_MIN_INTERVAL_SECONDS})"
        ),
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        help=(
            "run forever, hands-off: each feed on its own schedule (urlhaus 300 s, "
            "openphish/threatfox 600 s), exponential backoff on errors, heartbeat "
            "per cycle; defaults to --feeds all; stop with Ctrl-C/SIGTERM"
        ),
    )
    parser.add_argument(
        "--max-cycles",
        type=int,
        default=0,
        metavar="N",
        help="with --daemon: stop after N cycles (for tests and demos; default: unlimited)",
    )
    bench = parser.add_argument_group(
        "capacity benchmark",
        "offline, synthetic rows, isolated table; measures the store, NOT the live feed rate",
    )
    bench.add_argument(
        "--bench",
        action="store_true",
        help="run the capacity benchmark (bench.py) and exit; no feed is contacted",
    )
    bench.add_argument(
        "--rows", type=int, default=100_000, help="--bench: synthetic rows (default: 100000)"
    )
    bench.add_argument(
        "--batch", type=int, default=10_000, help="--bench: rows per insert (default: 10000)"
    )
    bench.add_argument(
        "--keep", action="store_true", help="--bench: keep incoming_threats_bench afterwards"
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


def _summary_line(name: str, stat: dict[str, Any]) -> str:
    return (
        f"[feed] {name}: fetched={stat['fetched']} mapped={stat['mapped']} "
        f"new={stat['new']} duplicates={stat['duplicates']} error={stat['error'] or 'none'}"
    )


def record_run_stats(
    client: clickhouse_connect.driver.client.Client | None,
    stats: Mapping[str, Mapping[str, Any]],
    *,
    table: str | None = None,
) -> clickhouse_connect.driver.client.Client | None:
    """Insert one `ingest_runs` row per feed attempt; NEVER raises.

    Creates the table if needed (idempotent). `client` may be None, in which
    case a connection is opened; the (possibly new) client is returned so the
    caller can close it. Any failure is logged as a warning only: telemetry
    must not be able to break ingestion.
    """
    try:
        if client is None:
            client = connect_clickhouse()
    except Exception as exc:  # noqa: BLE001 -- telemetry must never crash ingest
        log.warning("Could not record run stats (connect failed): %s", exc)
        return None
    try:
        table = runs_table_name(table)
        client.command(CREATE_RUNS_TABLE_TEMPLATE.format(table=table))
        run_ts = datetime.now(timezone.utc).replace(microsecond=0)
        rows = [
            (
                run_ts,
                name,
                int(s["fetched"]),
                int(s["mapped"]),
                int(s["new"]),
                int(s["duplicates"]),
                str(s["error"] or ""),
                min(int(s.get("duration_ms", 0)), 2**32 - 1),
            )
            for name, s in stats.items()
        ]
        client.insert(table, rows, column_names=RUN_COLUMN_NAMES)
        log.info("Recorded %d run row(s) in %s", len(rows), table)
    except Exception as exc:  # noqa: BLE001 -- telemetry must never crash ingest
        log.warning("Could not record run stats: %s", exc)
    return client


def run_once(args: argparse.Namespace, *, reset_schema: bool) -> int:
    """One poll over the selected feeds (`args.feed_names`); returns the exit code."""
    names: list[str] = getattr(args, "feed_names", None) or [DEFAULT_FEEDS]
    code, _stats = run_feeds(args, names, reset_schema=reset_schema)
    return code


def run_feeds(
    args: argparse.Namespace, names: Sequence[str], *, reset_schema: bool
) -> tuple[int, dict[str, dict[str, Any]]]:
    """One poll over `names`: fetch -> map -> dedup -> insert -> record stats.

    Each feed runs in its own try/except, so one failing feed is logged and the
    others still run. Exit code: 3 if any feed mapped nothing from a non-empty
    fetch (parser regression), else 1 if every feed failed, else 0. Also returns
    the per-feed stats (non-empty `error` = that feed failed), which the daemon
    uses for backoff. Unless `--dry-run`, one `ingest_runs` row per feed is
    written after the attempt (success or failure).
    """
    stats: dict[str, dict[str, Any]] = {
        n: {
            "fetched": 0,
            "mapped": 0,
            "new": 0,
            "duplicates": 0,
            "error": "",
            "duration_ms": 0,
        }
        for n in names
    }
    staged: dict[str, list[tuple[Any, ...]]] = {}
    nothing_mapped = False
    client = None
    exit_code: int | None = None
    try:
        for name in names:
            feed, stat = FEEDS[name], stats[name]
            started = time.monotonic()
            try:
                raw = feed.fetch(args.limit)
                stat["fetched"] = len(raw)
                rows = feed.map(raw, args)
                stat["mapped"] = len(rows)
                staged[name] = rows
            except NothingMappedError as exc:
                log.error("[%s] %s", name, exc)
                stat["error"] = "nothing mapped"
                nothing_mapped = True
            except RuntimeError as exc:
                log.error("[%s] %s", name, exc)
                stat["error"] = str(exc)[:120]
            except Exception as exc:  # noqa: BLE001 -- feed isolation by design
                log.exception("[%s] unexpected failure", name)
                stat["error"] = f"{type(exc).__name__}: {exc}"[:120]
            stat["duration_ms"] = int((time.monotonic() - started) * 1000)

        if staged and args.dry_run:
            for name, rows in staged.items():
                stats[name]["new"] = stats[name]["duplicates"] = "n/a"
                log.info("Dry run [%s]: %d row(s) mapped, database untouched", name, len(rows))
                for row in rows[:5]:
                    log.info("  %s", row)
                if len(rows) > 5:
                    log.info("  ... and %d more", len(rows) - 5)
        elif staged:
            client = connect_clickhouse()
            ensure_schema(client, recreate=reset_schema)
            for name, rows in staged.items():
                stat = stats[name]
                started = time.monotonic()
                try:
                    fresh, duplicates = drop_duplicates(client, rows)
                    log.info("[%s] Dedup: %d new, %d duplicates skipped", name, len(fresh), duplicates)
                    stat["new"] = insert_rows(client, fresh)
                    stat["duplicates"] = duplicates
                except Exception as exc:  # noqa: BLE001 -- feed isolation by design
                    log.exception("[%s] database step failed", name)
                    stat["error"] = f"{type(exc).__name__}: {exc}"[:120]
                stat["duration_ms"] += int((time.monotonic() - started) * 1000)
            report_table_state(client)
    except Exception as exc:  # noqa: BLE001 -- connection/schema failure
        if isinstance(exc, RuntimeError):
            log.error("%s", exc)
        else:
            log.exception("Unexpected failure during ingest")
        for stat in stats.values():
            if not stat["error"]:
                stat["error"] = f"{type(exc).__name__}: {exc}"[:120]
        exit_code = EXIT_RUNTIME
    finally:
        if not args.dry_run:
            client = record_run_stats(client, stats)
        if client is not None:
            client.close()
            log.debug("ClickHouse connection closed")

    if exit_code is not None:
        return exit_code, stats
    for name in names:
        print(_summary_line(name, stats[name]))
    if nothing_mapped:
        return EXIT_NOTHING_MAPPED, stats
    if all(stats[n]["error"] for n in names):
        return EXIT_RUNTIME, stats
    return EXIT_OK, stats


# --------------------------------------------------------------------------- #
# Daemon: per-feed scheduling with backoff
# --------------------------------------------------------------------------- #


class Scheduler:
    """Pure scheduling state for `--daemon`; time comes from an injectable clock.

    Every feed starts due. After a run, `record(name, ok)` schedules the next
    one `interval` seconds out: the feed's own `min_interval` (or the global
    override, never below DAEMON_MIN_INTERVAL_SECONDS), doubled per consecutive
    failure up to `cap`, and reset to the base after a success.
    """

    def __init__(
        self,
        names: Sequence[str],
        *,
        override: int | None = None,
        clock: Callable[[], float] = time.monotonic,
        cap: int = BACKOFF_CAP_SECONDS,
    ) -> None:
        self._clock = clock
        self._cap = cap
        self._base: dict[str, float] = {}
        for name in names:
            base = float(override) if override else float(FEEDS[name].min_interval)
            self._base[name] = max(base, float(DAEMON_MIN_INTERVAL_SECONDS))
        self._failures: dict[str, int] = {n: 0 for n in names}
        now = clock()
        self._next_due: dict[str, float] = {n: now for n in names}

    def interval(self, name: str) -> float:
        """Current wait for `name`: base * 2**failures, capped (never below base)."""
        base = self._base[name]
        return min(base * (2 ** self._failures[name]), max(self._cap, base))

    def due(self) -> list[str]:
        """Feeds whose next run time has arrived, in registration order."""
        now = self._clock()
        return [n for n, t in self._next_due.items() if t <= now]

    def seconds_until_next(self) -> float:
        """Seconds until the earliest feed is due (0 when one already is)."""
        return max(0.0, min(self._next_due.values()) - self._clock())

    def record(self, name: str, ok: bool) -> None:
        """Note the outcome of a run of `name` and schedule its next run."""
        self._failures[name] = 0 if ok else self._failures[name] + 1
        self._next_due[name] = self._clock() + self.interval(name)


def count_threat_rows() -> int | None:
    """Total rows in the threats table for the heartbeat; None if unavailable."""
    try:
        client = connect_clickhouse()
    except Exception:  # noqa: BLE001
        return None
    try:
        return int(client.query(f"SELECT count() FROM {table_name()}").first_row[0])
    except Exception:  # noqa: BLE001
        return None
    finally:
        client.close()


def run_daemon(
    args: argparse.Namespace,
    *,
    reset_schema: bool = False,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], Any] | None = None,
    runner: Callable[..., tuple[int, dict[str, dict[str, Any]]]] = run_feeds,
    count_rows: Callable[[], int | None] = count_threat_rows,
    install_signals: bool = True,
) -> int:
    """Run the selected feeds forever on their own schedules (until a signal).

    Each cycle logs a heartbeat, runs only the due feeds, and updates their
    schedule (backoff on failure, reset on success). SIGINT/SIGTERM stop the
    loop after the in-flight run finishes (a second signal aborts at once);
    `--max-cycles N` stops after N cycles. Failures never end the daemon.
    """
    names: list[str] = args.feed_names
    sched = Scheduler(names, override=args.interval or None, clock=clock)
    stop = threading.Event()
    wait = sleep if sleep is not None else stop.wait
    max_cycles = getattr(args, "max_cycles", None) or 0

    def _on_signal(signum: int, _frame: Any) -> None:
        if stop.is_set():
            raise KeyboardInterrupt
        log.info("Received signal %d; stopping after the current step", signum)
        stop.set()

    previous: dict[int, Any] = {}
    if install_signals:
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, _on_signal)

    cycle = 0
    log.info(
        "daemon started: feeds=%s intervals=%s",
        ",".join(names),
        {n: int(sched.interval(n)) for n in names},
    )
    try:
        while not stop.is_set():
            due = sched.due()
            if not due:
                wait(sched.seconds_until_next())
                continue
            cycle += 1
            total = count_rows()
            log.info(
                "[daemon] heartbeat cycle=%d due=%s total_rows=%s",
                cycle,
                ",".join(due),
                "unknown" if total is None else total,
            )
            try:
                code, stats = runner(args, due, reset_schema=reset_schema)
            except Exception:  # noqa: BLE001 -- the daemon must survive anything
                log.exception("[daemon] cycle %d crashed; backing off", cycle)
                code, stats = EXIT_RUNTIME, {}
            reset_schema = False  # never drop the table more than once
            for name in due:
                failed = bool(stats.get(name, {"error": "crashed"})["error"])
                sched.record(name, ok=not failed)
                if failed:
                    log.warning(
                        "[daemon] %s failed; retry in %ds", name, int(sched.interval(name))
                    )
            if max_cycles and cycle >= max_cycles:
                break
            if not stop.is_set():
                log.info("[daemon] next run in %ds", int(sched.seconds_until_next()))
    except KeyboardInterrupt:
        pass
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    log.info("daemon stopped (cycles=%d)", cycle)
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    if args.self_test:
        return run_self_test()

    if args.bench:
        import bench  # local import: bench imports this module

        return bench.cli(args.rows, args.batch, seed=bench.DEFAULT_SEED,
                         keep=args.keep, verbose=args.verbose)

    if args.limit < 1:
        log.error("--limit must be >= 1 (got %d)", args.limit)
        return EXIT_USAGE
    if not str(args.threat_type).strip():
        log.error("--threat-type must not be empty (use 'all' to disable filtering)")
        return EXIT_USAGE
    if args.max_cycles < 0 or (args.max_cycles and not args.daemon):
        log.error("--max-cycles must be >= 0 and requires --daemon")
        return EXIT_USAGE
    if args.daemon and args.interval and args.interval < DAEMON_MIN_INTERVAL_SECONDS:
        log.error(
            "--interval must be >= %d seconds in --daemon mode (got %d)",
            DAEMON_MIN_INTERVAL_SECONDS,
            args.interval,
        )
        return EXIT_USAGE
    if args.daemon and args.dry_run:
        log.error("--daemon and --dry-run cannot be combined")
        return EXIT_USAGE
    if not args.daemon and args.interval and args.interval < MIN_POLL_INTERVAL_SECONDS:
        log.error(
            "--interval must be >= %d seconds to respect URLhaus rate limits (got %d)",
            MIN_POLL_INTERVAL_SECONDS,
            args.interval,
        )
        return EXIT_USAGE
    if args.interval and args.dry_run:
        log.error("--interval and --dry-run cannot be combined")
        return EXIT_USAGE

    try:
        args.feed_names = parse_feed_names(
            args.feeds or ("all" if args.daemon else DEFAULT_FEEDS)
        )
    except ValueError as exc:
        log.error("%s", exc)
        return EXIT_USAGE

    load_environment()
    try:
        table_name()
    except RuntimeError as exc:
        log.error("%s", exc)
        return EXIT_USAGE

    try:
        runs_table_name()
    except RuntimeError as exc:
        log.error("%s", exc)
        return EXIT_USAGE

    if args.daemon:
        return run_daemon(args, reset_schema=args.reset_schema)

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
