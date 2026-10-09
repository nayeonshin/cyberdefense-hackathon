#!/usr/bin/env python3
"""
threatfeed -- the Member 1 -> Member 2 interface (see INTERFACE.md).

    from threatfeed import get_pending_targets, update_takedown_status

    for target in get_pending_targets(5):
        print(target["domain"], target["url_count"], target["target_urls"][:1])
    update_takedown_status("TAKEN_DOWN", domain="evil.example")

Run directly to print the top 5 pending targets (the demo command):

    .venv/bin/python threatfeed.py

Connection settings come from clickhouse.env / .env exactly as for ingest.py
(the same helpers are reused). `THREATS_TABLE` (default `incoming_threats`)
selects the table, which lets the smoke test use an isolated one.

Every value that comes from a caller (domain, event_id, status, limit) is
bound as a ClickHouse query parameter; nothing is formatted into SQL. The
table name is the only interpolated identifier and is validated first.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from typing import Any

import clickhouse_connect

from ingest import connect_clickhouse, load_environment, table_name

__all__ = [
    "VALID_STATUSES",
    "get_pending_targets",
    "update_takedown_status",
]

log = logging.getLogger("threatfeed")

VALID_STATUSES: frozenset[str] = frozenset(
    {"PENDING", "SCANNING", "SCANNED", "TAKEN_DOWN", "FALSE_POSITIVE"}
)
MAX_URLS_PER_TARGET = 10

_env_loaded = False


def _client() -> clickhouse_connect.driver.client.Client:
    """Open a ClickHouse client, loading the env files once per process."""
    global _env_loaded
    if not _env_loaded:
        load_environment()
        _env_loaded = True
    return connect_clickhouse()


def _utc(epoch: Any) -> datetime:
    """Epoch seconds (as returned by toUnixTimestamp) -> UTC-aware datetime."""
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc)


def get_pending_targets(limit: int = 5) -> list[dict[str, Any]]:
    """Return the highest-velocity PENDING targets, one row per domain.

    Ordered by distinct URL count descending, then most recent `timestamp`
    descending. Keys per row:

        domain        str
        url_count     int            uniqExact(target_url) over PENDING rows
        first_seen    datetime (UTC) min(timestamp) over PENDING rows
        last_seen     datetime (UTC) max(timestamp) over PENDING rows
        target_urls   list[str]      up to 10 pending URLs, newest first   (additive)
        threat_types  list[str]      distinct threat types, sorted         (additive)
        ip_address    str            any non-empty ip_address, else ''     (additive)

    Read-only. Raises ValueError when `limit` is not an int >= 1; returns []
    when nothing is pending.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError(f"limit must be an int >= 1 (got {limit!r})")

    table = table_name()
    query = f"""
        SELECT
            domain,
            uniqExact(target_url)              AS url_count,
            toUnixTimestamp(min(`timestamp`))  AS first_epoch,
            toUnixTimestamp(max(`timestamp`))  AS last_epoch,
            arraySlice(
                arrayDistinct(arrayMap(
                    x -> x.2,
                    arrayReverseSort(groupArray((`timestamp`, target_url)))
                )),
                1, {{max_urls:UInt32}}
            )                                  AS target_urls,
            arraySort(groupUniqArray(threat_type)) AS threat_types,
            anyIf(ip_address, ip_address != '') AS ip_address
        FROM {table}
        WHERE takedown_status = {{pending:String}}
        GROUP BY domain
        ORDER BY url_count DESC, max(`timestamp`) DESC, domain ASC
        LIMIT {{limit:UInt32}}
    """
    client = _client()
    try:
        result = client.query(
            query,
            parameters={
                "pending": "PENDING",
                "limit": limit,
                "max_urls": MAX_URLS_PER_TARGET,
            },
        )
    finally:
        client.close()

    targets: list[dict[str, Any]] = []
    for domain, url_count, first_epoch, last_epoch, urls, threats, ip in result.result_rows:
        targets.append(
            {
                "domain": domain,
                "url_count": int(url_count),
                "first_seen": _utc(first_epoch),
                "last_seen": _utc(last_epoch),
                "target_urls": list(urls),
                "threat_types": list(threats),
                "ip_address": ip or "",
            }
        )
    return targets


def update_takedown_status(
    status: str,
    *,
    domain: str | None = None,
    event_id: str | None = None,
    client=None,
) -> int:
    """Set `takedown_status` for every row of `domain`, or for one `event_id`.

    Exactly one selector must be given. `status` must be one of
    VALID_STATUSES. Counts the matching rows, then issues
    `ALTER TABLE ... UPDATE` with `mutations_sync=1`, so the change is visible
    to the next `get_pending_targets()` call. Returns the matched row count
    (0 means nothing matched and no mutation was issued).
    """
    if status not in VALID_STATUSES:
        raise ValueError(
            f"status must be one of {sorted(VALID_STATUSES)} (got {status!r})"
        )
    if (domain is None) == (event_id is None):
        raise ValueError("pass exactly one of domain= or event_id=")

    if domain is not None:
        column, value = "domain", domain
    else:
        column, value = "event_id", event_id
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{column} must be a non-empty string (got {value!r})")

    table = table_name()
    where = f"{column} = {{selector:String}}"
    params = {"selector": value, "status": status}

    owned = client is None
    if owned:
        client = _client()
    try:
        matched = int(
            client.query(
                f"SELECT count() FROM {table} WHERE {where}", parameters=params
            ).first_row[0]
        )
        if matched == 0:
            log.info("update_takedown_status: no rows match %s=%r", column, value)
            return 0
        client.command(
            f"ALTER TABLE {table} UPDATE takedown_status = {{status:String}} WHERE {where}",
            parameters=params,
            settings={"mutations_sync": 1},
        )
    finally:
        if owned:
            client.close()

    log.info(
        "update_takedown_status: %s=%r -> %s (%d row(s))", column, value, status, matched
    )
    return matched


def _demo() -> int:
    logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(levelname)s] %(message)s")
    try:
        targets = get_pending_targets(5)
    except Exception as exc:  # noqa: BLE001 -- demo entrypoint, report and exit
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"Top {len(targets)} pending target(s) from {table_name()}:")
    if not targets:
        print("  (none pending -- run ingest.py first)")
    for rank, t in enumerate(targets, 1):
        print(
            f"{rank}. {t['domain']:<40} urls={t['url_count']:<3} "
            f"ip={t['ip_address'] or '-':<15} threats={','.join(t['threat_types'])} "
            f"last_seen={t['last_seen'].isoformat()}"
        )
        for url in t["target_urls"][:3]:
            print(f"     {url}")
    return 0


if __name__ == "__main__":
    sys.exit(_demo())
