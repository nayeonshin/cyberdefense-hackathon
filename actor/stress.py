"""Stress the pipeline on the real ClickHouse service, with every outside channel recorded.

    python -m actor.stress            400 real threat URLs plus the hostile rows
    python -m actor.stress 2000       more of them
    python -m actor.stress lookups    latency and correctness of the history lookup

The bench runs the Actor against a stand-in table. This runs it against the database:
real inserts, real `FINAL` reads, real history lookups, on tables of its own
(`stress_threats`, `stress_events`, `stress_actions`) so the team's tables stay untouched.
Reports, mail and feed files go to recorders and a temporary folder, never to the network.
"""
import contextlib
import json
import os
import random
import statistics
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from . import history, intake, policy as policy_module
from .actions import xarf_email
from .bench.run import CHANNEL_ACTIONS, FEED_URL, Wire, _enrichment
from .ledger import Ledger, clickhouse_client

RESULT = Path(__file__).parent / "bench" / "stress.json"

THREATS_DDL = """
CREATE TABLE stress_threats (
    event_id String, target_url String, domain String, ip_address String,
    timestamp DateTime, threat_type String, takedown_status String DEFAULT 'PENDING',
    feed_source LowCardinality(String) DEFAULT 'urlhaus', first_seen DateTime DEFAULT now()
) ENGINE = MergeTree ORDER BY timestamp
"""
EVENTS_DDL = """
CREATE TABLE stress_events (
    event_id String, target_url String, timestamp DateTime64(3, 'UTC'),
    semgrep_detected Nullable(Bool), confidence_score Nullable(Float32),
    evidence String DEFAULT '', action_status LowCardinality(String) DEFAULT 'PENDING',
    proof_url String DEFAULT '', updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(updated_at) ORDER BY event_id
"""

# Rows no scanner should produce, marked VERIFIED anyway. None may lead to an action
# against the named target; `url_only` ones may be reported per URL but never mailed.
HOSTILE = [
    ("traversal-id", "../../../etc/passwd", "https://traversal.bad.example/login", 0.99, "none"),
    ("no-scheme", "hostile-no-scheme", "traversal.bad.example/login", 0.99, "none"),
    ("javascript", "hostile-javascript", "javascript:alert(1)", 0.99, "none"),
    ("file-scheme", "hostile-file", "file:///etc/passwd", 0.99, "none"),
    ("newline", "hostile-newline", "https://newline.bad.example/a\nBcc: victim@example.org", 0.99, "none"),
    ("empty-url", "hostile-empty", "", 0.99, "none"),
    ("space-host", "hostile-space", "https://bad host.example/", 0.99, "none"),
    ("long-url", "hostile-long", "https://long.bad.example/" + "a" * 60000, 0.99, "any"),
    ("unicode", "hostile-unicode", "https://bücher.bad.example/ログイン", 0.99, "any"),
    ("null-confidence", "hostile-null-confidence", "https://nullconf.bad.example/login", None, "none"),
    ("not-detected", "hostile-not-detected", "https://notdetected.bad.example/login", 0.99, "none"),
    ("low-confidence", "hostile-low", "https://lowconf.bad.example/login", 0.40, "none"),
    ("private-ip", "hostile-private", "http://10.0.0.5/admin", 0.99, "none"),
    ("loopback", "hostile-loopback", "http://127.0.0.1:8099/site", 0.99, "controlled"),
    ("metadata", "hostile-metadata", "http://169.254.169.254/latest/meta-data/", 0.99, "none"),
    ("google", "hostile-google", "https://accounts.google.com/signin", 0.99, "url_only"),
    ("github-pages", "hostile-github", "https://someone.github.io/login", 0.99, "url_only"),
    ("trailing-dot", "hostile-dot", "https://www.paypal.com./signin", 0.99, "url_only"),
    ("userinfo", "hostile-userinfo", "https://google.com@userinfo.bad.example/login", 0.99, "any"),
    ("lookalike", "hostile-lookalike", "https://google.com.lookalike.bad.example/login", 0.99, "any"),
    ("ipv6", "hostile-ipv6", "http://[2001:db8::1]/login", 0.99, "any"),
    ("sql", "hostile-sql", "https://sql.bad.example/?q=' OR 1=1; DROP TABLE stress_events --", 0.99, "none"),
]
PLATFORM_HOSTS = ("google.com", "github.io", "paypal.com")


def _percentile(values: list, q: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


def build(client, count: int) -> dict:
    """Fill the stress tables. Returns what must hold for each event afterwards."""
    for table, ddl in (("stress_threats", THREATS_DDL), ("stress_events", EVENTS_DDL)):
        client.command(f"DROP TABLE IF EXISTS {table} SYNC")
        client.command(ddl)
    client.command("DROP TABLE IF EXISTS stress_actions SYNC")
    real = client.query(
        "SELECT source, event_id, url, threat_type FROM threat_history "
        f"ORDER BY cityHash64(url) LIMIT {int(count)}").result_rows
    now = datetime.now(timezone.utc).replace(microsecond=0)
    rng = random.Random(7)
    expect, threats, events = {}, [], []

    def add(event_id, url, source, threat, status, detected, confidence, kind):
        when = now - timedelta(seconds=len(expect))
        threats.append([event_id, url, "", "", when, threat, "SCANNED", source])
        events.append([event_id, url, when, detected, confidence, "Semgrep rule matched", status, ""])
        expect[event_id] = kind

    for n, (source, source_id, url, threat) in enumerate(real):
        event_id = f"s{n:05d}-{source_id}"[:60]
        roll = rng.random()
        if roll < 0.60:
            add(event_id, url, source, threat, "VERIFIED", True, 0.96, "any")
        elif roll < 0.75:
            add(event_id, url, source, threat, "VERIFIED", True, 0.85, "protect")
        elif roll < 0.85:
            add(event_id, url, source, threat, "VERIFIED", True, 0.55, "none")
        elif roll < 0.95:
            add(event_id, url, source, threat, "REJECTED", False, 0.10, "untouched")
        else:
            add(event_id, url, source, threat, "FETCH_FAILED", None, None, "untouched")
    for name, event_id, url, confidence, kind in HOSTILE:
        add(event_id, url, "urlhaus", "phishing", "VERIFIED", name != "not-detected", confidence, kind)
    # The same event written twice by the scanner, and one event_id reused for another URL.
    add("dup-event", "https://dup.bad.example/login", "urlhaus", "phishing", "VERIFIED", True, 0.96, "any")
    events.append(list(events[-1]))
    for start in range(0, len(threats), 5000):
        client.insert("stress_threats", threats[start:start + 5000], column_names=[
            "event_id", "target_url", "domain", "ip_address", "timestamp", "threat_type",
            "takedown_status", "feed_source"])
        client.insert("stress_events", events[start:start + 5000], column_names=intake.EVENT_COLUMNS)
    return expect


def run(count: int) -> dict:
    client = clickhouse_client()
    if client is None:
        sys.exit("CLICKHOUSE_HOST and CLICKHOUSE_PASSWORD must be set in .env")
    started = time.perf_counter()
    expect = build(client, count)
    print(f"{len(expect)} events in stress_events ({time.perf_counter() - started:.1f} s to load)")

    sandbox = Path(tempfile.mkdtemp(prefix="actor-stress-"))
    feed_dir, outbox, ledger_dir = sandbox / "feed", sandbox / "outbox", sandbox / "ledger"
    for folder in (feed_dir, outbox, ledger_dir):
        folder.mkdir()
    env = {
        "EVENTS_TABLE": "stress_threats", "VERDICTS_TABLE": "stress_events",
        "ACTIONS_TABLE": "stress_actions", "HISTORY_LOOKUP": "1",
        "LIVE_FEED": "1", "LIVE_URLSCAN": "1", "LIVE_NETCRAFT": "1", "LIVE_ABUSEIPDB": "1",
        "LIVE_EMAIL": "0", "SMTP_LIVE_HOST": "", "ACTOR_STOP": "0",
        "URLSCAN_API_KEY": "stress", "ABUSEIPDB_API_KEY": "stress",
        "REPORTER_EMAIL": "reporter@stress.test", "REPORTER_ORG": "Stress",
        "NETCRAFT_REPORT_URL": "https://report.netcraft.com/api/v3/report/urls",
        "FEED_REPO_DIR": str(feed_dir), "FEED_PUBLIC_URL": FEED_URL,
        "OUTBOX_DIR": str(outbox), "MOCK_REGISTRAR_URL": "http://localhost:8099",
    }
    wire, policy = Wire(), policy_module.load()
    ledger = Ledger(ledger_dir / "actions.jsonl")
    problems, passes, per_pass = [], 0, []

    def fake_enrich(host, offline=False):
        return _enrichment("private" if host.startswith(("10.", "169.254.")) else "unique", host)

    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.dict(os.environ, env))
        for target, replacement in [
            ("requests.post", wire.post), ("requests.head", wire.head), ("requests.get", wire.get),
            ("smtplib.SMTP", wire.smtp()),
            ("actor.dispatch.enrich", fake_enrich), ("actor.recheck.enrich", fake_enrich),
        ]:
            stack.enter_context(mock.patch(target, replacement))
        history._recent.clear()
        acting = time.perf_counter()
        while True:
            pass_started = time.perf_counter()
            try:
                receipts = intake.run_verified(client, live=True, ledger=ledger, policy=policy)
            except Exception as exc:
                problems.append(f"pass {passes + 1} crashed: {type(exc).__name__}: {str(exc)[:200]}")
                break
            if not receipts:
                break
            passes += 1
            per_pass.append(time.perf_counter() - pass_started)
            if passes > len(expect):
                problems.append("the queue never drains: a row stays VERIFIED after it was handled")
                break
        seconds = time.perf_counter() - acting
        try:
            again = intake.run_verified(client, live=True, ledger=ledger, policy=policy)
        except Exception as exc:
            again = []
            problems.append(f"second run crashed: {type(exc).__name__}: {str(exc)[:200]}")
        if again:
            problems.append(f"a second run produced {len(again)} more receipts")

    # What the database says afterwards.
    final = {row[0]: (row[1], row[2]) for row in client.query(
        "SELECT event_id, action_status, proof_url FROM stress_events FINAL").result_rows}
    receipts = ledger.all()
    by_event = {}
    for r in receipts:
        by_event.setdefault(r["event_id"], []).append(r)
    handled = sum(1 for kind in expect.values() if kind != "untouched")
    for event_id, kind in expect.items():
        status, proof = final.get(event_id, ("MISSING", ""))
        sent = {r["action"] for r in by_event.get(event_id, [])
                if r["status"] in ("SENT", "SINK") and not r["dry_run"]}
        if kind == "untouched":
            if status not in ("REJECTED", "FETCH_FAILED") or event_id in by_event:
                problems.append(f"{event_id}: a row the scanner did not verify was touched ({status})")
            continue
        if status == "VERIFIED":
            problems.append(f"{event_id}: still VERIFIED, never handled")
        if status == "PUBLISHED_TAKEDOWN" and not proof:
            problems.append(f"{event_id}: published without a proof link")
        if kind == "none" and sent:
            problems.append(f"{event_id}: must not act, but sent {sorted(sent)}")
        if kind == "protect" and sent - {"feed"}:
            problems.append(f"{event_id}: feed only at this confidence, but sent {sorted(sent)}")
        if kind == "url_only" and sent - {"feed", "urlscan", "netcraft"}:
            problems.append(f"{event_id}: platform URL, but sent {sorted(sent)}")
        if kind == "controlled" and sent - {"mock_registrar", "notify_host", "notify_registrar"}:
            problems.append(f"{event_id}: controlled target went to a real channel {sorted(sent)}")
    for call in wire.http:
        if call["host"] not in CHANNEL_ACTIONS:
            problems.append(f"request to unapproved host {call['host'] or call['url'][:40]}")
    for message in wire.mail:
        if message["To"] != xarf_email.SINK_ADDRESS:
            problems.append(f"mail addressed to real recipient {message['To']}")
    for r in receipts:
        if r["action"] in ("notify_host", "notify_registrar", "abuseipdb") and r["status"] in ("SENT", "SINK") \
                and any(r["domain"] == p or r["domain"].endswith("." + p) for p in PLATFORM_HOSTS):
            problems.append(f"{r['event_id']}: {r['action']} against a shared platform")
    stored = client.query("SELECT count() FROM stress_actions").result_rows[0][0]
    if stored != len(receipts):
        problems.append(f"{len(receipts)} receipts written, {stored} arrived in ClickHouse")
    outcomes = {}
    for event_id, kind in expect.items():
        if kind != "untouched":
            status = final.get(event_id, ("MISSING", ""))[0]
            outcomes[status] = outcomes.get(status, 0) + 1

    result = {
        "ran_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "events": len(expect), "handled": handled, "passes": passes,
        "seconds": round(seconds, 1), "events_per_second": round(handled / seconds, 2) if seconds else 0,
        "receipts": len(receipts), "receipts_in_clickhouse": stored,
        "requests_recorded": len(wire.http), "mails_recorded": len(wire.mail),
        "outcomes": outcomes, "problems": problems[:50], "problem_count": len(problems),
    }
    print(f"handled {handled} verified events in {seconds:.1f} s over {passes} passes "
          f"({result['events_per_second']} per second)")
    print(f"receipts {len(receipts)} written, {stored} in ClickHouse; "
          f"{len(wire.http)} requests and {len(wire.mail)} mails recorded, none sent")
    print(f"outcomes: {outcomes}")
    print(f"problems: {len(problems)}")
    for line in problems[:25]:
        print(f"  {line}")
    return result


def lookups(samples: int = 400, threads: int = 16) -> dict:
    """History lookups: same answer from every table, and how long they take under load."""
    client = clickhouse_client()
    hosts = [r[0] for r in client.query(
        "SELECT host FROM threat_history WHERE host != '' GROUP BY host "
        f"ORDER BY cityHash64(host) LIMIT {int(samples)}").result_rows]
    odd = ["", "'", "\"; DROP TABLE threat_history --", "a" * 5000, "bücher.example", "\x00",
           "no-such-host.invalid", "{host:String}", "%s", "127.0.0.1", "[::1]"]
    tables = ["threat_history"]
    if client.query("EXISTS TABLE threat_history_scale").result_rows[0][0]:
        tables.append("threat_history_scale")
    out, answers = {"problems": []}, {}
    for table in tables:
        rows = client.query(f"SELECT count() FROM {table}").result_rows[0][0]
        with mock.patch.dict(os.environ, {"HISTORY_TABLE": table}):
            for value in odd:
                try:
                    found = history.host_history(client, value)
                    if value not in ("127.0.0.1",) and found["urls_on_record"] and table == "threat_history" \
                            and value in ("'", "%s", "{host:String}", "\x00", "no-such-host.invalid"):
                        out["problems"].append(f"{table}: {value!r} matched {found['urls_on_record']} rows")
                except Exception as exc:
                    out["problems"].append(f"{table}: lookup of {value[:30]!r} failed: {type(exc).__name__}")
            single = []
            for host in hosts:
                found = history.host_history(client, host)
                single.append(found["lookup_ms"])
                answers.setdefault(host, {})[table] = found["urls_on_record"]

            def one(host):
                mine = clickhouse_client()
                try:
                    return history.host_history(mine, host)["lookup_ms"]
                finally:
                    mine.close()

            started = time.perf_counter()
            with ThreadPoolExecutor(max_workers=threads) as pool:
                parallel = list(pool.map(one, hosts))
            wall = time.perf_counter() - started
        out[table] = {
            "rows": rows, "lookups": len(hosts),
            "median_ms": round(statistics.median(single), 1), "p95_ms": round(_percentile(single, 0.95), 1),
            "p99_ms": round(_percentile(single, 0.99), 1), "max_ms": round(max(single), 1),
            "parallel_threads": threads, "parallel_per_second": round(len(hosts) / wall, 1),
            "parallel_p95_ms": round(_percentile(parallel, 0.95), 1),
        }
        print(f"{table}: {rows:,} rows, {len(hosts)} lookups, median {out[table]['median_ms']} ms, "
              f"p95 {out[table]['p95_ms']} ms, p99 {out[table]['p99_ms']} ms; "
              f"{threads} at once: {out[table]['parallel_per_second']} per second")
    differing = [h for h, a in answers.items() if len(set(a.values())) > 1]
    if differing:
        out["problems"].append(f"{len(differing)} hosts answer differently across tables, e.g. {differing[0]}")
    print(f"problems: {len(out['problems'])}")
    for line in out["problems"]:
        print(f"  {line}")
    return out


def main() -> None:
    saved = json.loads(RESULT.read_text(encoding="utf-8")) if RESULT.exists() else {}
    if len(sys.argv) > 1 and sys.argv[1] == "lookups":
        saved["lookups"] = lookups()
    else:
        saved["pipeline"] = run(int(sys.argv[1]) if len(sys.argv) > 1 else 400)
    RESULT.write_text(json.dumps(saved, indent=2) + "\n", encoding="utf-8")
    failed = saved.get("pipeline", {}).get("problem_count", 0) + len(saved.get("lookups", {}).get("problems", []))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
