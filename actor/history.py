"""Real threat history in ClickHouse: load it, replay the Actor over it, look hosts up in it.

    python -m actor.history load urlhaus_recent.csv phishing_active.txt openphish.txt
    python -m actor.history replay             every row through the Actor's parser and policy
    python -m actor.history lookup <host>      what the Actor adds to a report about this host

The replay answers one question on real data instead of hand-written scenarios: if the
scanner verified this URL, what would the Actor do, and does it ever fall over? Nothing is
sent; it is the parser and the rules of engagement only, with no DNS and no network.
"""
import csv
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from . import config, policy as policy_module
from .contract import Verdict
from .enrich import Enrichment, is_ip
from .ledger import clickhouse_client

HISTORY_DDL = """
CREATE TABLE IF NOT EXISTS threat_history (
    source LowCardinality(String),
    event_id String,
    url String,
    host String,
    threat_type LowCardinality(String),
    first_seen DateTime('UTC')
) ENGINE = MergeTree ORDER BY (host, first_seen)
"""
REPLAY_DDL = """
CREATE TABLE IF NOT EXISTS replay_decisions (
    run_id String,
    source LowCardinality(String),
    event_id String,
    host String,
    outcome LowCardinality(String),
    actions LowCardinality(String),
    reason LowCardinality(String)
) ENGINE = MergeTree ORDER BY (run_id, outcome, host)
"""
HISTORY_COLUMNS = ["source", "event_id", "url", "host", "threat_type", "first_seen"]
REPLAY_COLUMNS = ["run_id", "source", "event_id", "host", "outcome", "actions", "reason"]
BATCH = 50_000


def history_table() -> str:
    name = config.get("HISTORY_TABLE", "threat_history")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,80}", name):
        raise ValueError("HISTORY_TABLE is not a plain table name")
    return name


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _rows(path: Path):
    """(source, event_id, url, threat_type, first_seen) from one downloaded file."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    name = path.name.lower()
    if name.endswith(".csv"):                       # URLhaus export
        with path.open(encoding="utf-8", errors="replace", newline="") as handle:
            for row in csv.reader(line for line in handle if not line.startswith("#")):
                if len(row) >= 6:
                    try:
                        seen = datetime.strptime(row[1], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                    except ValueError:
                        seen = now
                    yield "urlhaus", row[0], row[2], row[5], seen
        return
    source = "openphish" if "openphish" in name else "phishing-database"
    with path.open(encoding="utf-8", errors="replace") as handle:
        for n, line in enumerate(handle, start=1):
            url = line.strip()
            if url:
                yield source, f"{source[:2]}-{n}", url, "phishing", now


def load(paths: list) -> None:
    client = clickhouse_client()
    client.command(HISTORY_DDL)
    client.command("TRUNCATE TABLE threat_history")
    total, started = 0, time.perf_counter()
    for path in map(Path, paths):
        batch = []
        for source, event_id, url, threat, seen in _rows(path):
            batch.append([source, event_id, url, _host(url), threat, seen])
            if len(batch) >= BATCH:
                client.insert("threat_history", batch, column_names=HISTORY_COLUMNS)
                total, batch = total + len(batch), []
        if batch:
            client.insert("threat_history", batch, column_names=HISTORY_COLUMNS)
            total += len(batch)
        print(f"  {path.name}: loaded, {total} rows so far")
    seconds = time.perf_counter() - started
    print(f"loaded {total} rows in {seconds:.1f} s ({total / seconds:,.0f} rows/s)")


def decide_row(source: str, event_id: str, url: str, threat: str, policy: dict) -> tuple:
    """(outcome, actions, reason) for one historical row, as if the scanner had verified it."""
    try:
        verdict = Verdict.from_dict({
            "event_id": event_id, "target_url": url, "timestamp": "", "semgrep_detected": True,
            "confidence_score": 0.96, "evidence": "replay", "threat_type": threat,
            "corroborated": True})
    except ValueError as exc:
        return "refused", "", str(exc)
    host = verdict.host
    enrichment = Enrichment(domain=host, ips=[host] if is_ip(host) else [])
    decision = policy_module.decide(verdict, enrichment, policy)
    if not decision.plans:
        return "withheld", "", decision.skipped[0][1] if decision.skipped else ""
    scope = "act, URL only" if policy_module.is_allowlisted(host, policy) else "act"
    return scope, "+".join(decision.actions()), ""


def replay(limit: int = 0) -> None:
    client = clickhouse_client()
    client.command(REPLAY_DDL)
    policy = policy_module.load()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    query = "SELECT source, event_id, url, threat_type FROM threat_history" + (f" LIMIT {int(limit)}" if limit else "")
    total, crashes, batch, started = 0, [], [], time.perf_counter()
    with client.query_row_block_stream(query) as stream:
        for block in stream:
            for source, event_id, url, threat in block:
                try:
                    outcome, actions, reason = decide_row(source, event_id, url, threat, policy)
                except Exception as exc:     # the point of the exercise: this must never happen
                    outcome, actions, reason = "crash", "", f"{type(exc).__name__}: {exc}"[:120]
                    if len(crashes) < 20:
                        crashes.append((url[:120], reason))
                batch.append([run_id, source, event_id, _host(url), outcome, actions, reason])
                total += 1
            if len(batch) >= BATCH:
                client.insert("replay_decisions", batch, column_names=REPLAY_COLUMNS)
                batch = []
    if batch:
        client.insert("replay_decisions", batch, column_names=REPLAY_COLUMNS)
    seconds = time.perf_counter() - started
    print(f"run {run_id}: {total} real URLs through the Actor in {seconds:.1f} s "
          f"({total / seconds:,.0f} per second)")
    summary = client.query(
        "SELECT outcome, if(startsWith(outcome, 'act'), actions, reason) AS detail, count() AS n "
        "FROM replay_decisions WHERE run_id = {run:String} GROUP BY outcome, detail ORDER BY n DESC LIMIT 25",
        parameters={"run": run_id})
    for outcome, detail, n in summary.result_rows:
        print(f"  {n:>8}  {outcome:<9} {detail}")
    print(f"crashes: {len(crashes)}")
    for url, reason in crashes:
        print(f"  {reason}  <-  {url!r}")


_client = None
_recent = {}        # host -> (time, result): one dispatch asks twice within a moment


def lookup(host: str):
    """History for a report, or None when the lookup is off, unconfigured or fails."""
    global _client
    if not config.flag("HISTORY_LOOKUP"):
        return None
    try:
        if _client is None:
            _client = clickhouse_client()
        if _client is None:
            return None
        cached = _recent.get(host)
        if cached and time.monotonic() - cached[0] < 60:
            found = cached[1]
        else:
            found = host_history(_client, host)
            _recent[host] = (time.monotonic(), found)
        return found if found["urls_on_record"] else None
    except Exception:
        return None


# Only URLhaus rows carry a real date; the plain URL lists were stamped at load time.
RECORD = ("count(), minIf(first_seen, source = 'urlhaus'), maxIf(first_seen, source = 'urlhaus'), "
          "arrayStringConcat(arraySort(groupUniqArray(source)), ', '), countIf(source = 'urlhaus')")


def _record(host: str, row, started: float) -> dict:
    return {"host": host, "urls_on_record": row[0],
            "first_seen": row[1].strftime("%Y-%m-%d") if row[4] else "",
            "last_seen": row[2].strftime("%Y-%m-%d") if row[4] else "",
            "sources": row[3], "lookup_ms": round((time.perf_counter() - started) * 1000, 1)}


def host_history(client, host: str) -> dict:
    """What the history table knows about a host. One lookup on the table's sort key."""
    started = time.perf_counter()
    row = client.query(f"SELECT {RECORD} FROM {history_table()} WHERE host = {{host:String}}",
                       parameters={"host": host}).result_rows[0]
    return _record(host, row, started)


def prime(hosts: list) -> None:
    """Look a whole batch of hosts up in one query, so the lookups that follow are answered here."""
    global _client
    hosts = sorted({h for h in hosts if h})
    if not hosts or not config.flag("HISTORY_LOOKUP"):
        return
    try:
        if _client is None:
            _client = clickhouse_client()
        if _client is None:
            return
        started = time.perf_counter()
        rows = _client.query(
            f"SELECT host, {RECORD} FROM {history_table()} WHERE host IN {{hosts:Array(String)}} "
            "GROUP BY host", parameters={"hosts": hosts}).result_rows
        found = {row[0]: _record(row[0], row[1:], started) for row in rows}
        empty = (0, None, None, "", 0)
        now = time.monotonic()
        for host in hosts:
            _recent[host] = (now, found.get(host) or _record(host, empty, started))
    except Exception:
        return


def main() -> None:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "load" and len(sys.argv) > 2:
        load(sys.argv[2:])
    elif command == "replay":
        replay(int(sys.argv[2]) if len(sys.argv) > 2 else 0)
    elif command == "lookup" and len(sys.argv) > 2:
        print(host_history(clickhouse_client(), sys.argv[2]))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
