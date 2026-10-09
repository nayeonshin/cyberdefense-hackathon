"""Live checks: does every real channel answer right now?

    python -m actor.live           read-only checks (credentials, reachability, latency)
    python -m actor.live --full    also the checks that leave a trace: a public urlscan
                                   scan, a self-test entry pushed to the feed and removed
                                   again, a report against the controlled target

The bench proves the decisions with every channel replaced by a recorder. This proves the
channels themselves. Results go to actor/bench/live.json and to ClickHouse (`live_checks`).
"""
import argparse
import json
import os
import smtplib
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import requests

from . import config, evidence, policy as policy_module
from .actions import Context, feed
from .contract import Verdict, now_iso
from .enrich import Enrichment
from .ledger import clickhouse_client

OUT = Path(__file__).parent / "bench" / "live.json"
DDL = """
CREATE TABLE IF NOT EXISTS live_checks (
    checked_at DateTime64(3, 'UTC'),
    channel LowCardinality(String),
    provider LowCardinality(String),
    status LowCardinality(String),
    latency_ms UInt32,
    detail String,
    proof_url String
) ENGINE = MergeTree ORDER BY (checked_at, channel)
"""


def _timed(function):
    started = time.perf_counter()
    try:
        status, detail, proof = function()
    except Exception as exc:
        status, detail, proof = "FAIL", f"{type(exc).__name__}: {str(exc)[:140]}", ""
    return status, int((time.perf_counter() - started) * 1000), detail, proof


def check_clickhouse_write():
    client = clickhouse_client()
    if client is None:
        return "SKIP", "CLICKHOUSE_HOST or CLICKHOUSE_PASSWORD not set", ""
    client.command(DDL)
    client.insert("live_checks", [[datetime.now(timezone.utc), "probe", "ClickHouse", "OK", 0, "", ""]],
                  column_names=["checked_at", "channel", "provider", "status", "latency_ms", "detail", "proof_url"])
    rows = client.query("SELECT count() FROM live_checks").result_rows[0][0]
    return "OK", f"insert and count, {rows} rows in live_checks", ""


def check_clickhouse_lookup():
    client = clickhouse_client()
    if client is None:
        return "SKIP", "not configured", ""
    result = client.query("SELECT count(), uniqExact(domain) FROM actions WHERE NOT dry_run")
    receipts, domains = result.result_rows[0]
    return "OK", f"{receipts} live receipts over {domains} domains", ""


def check_scanner():
    """Member 2's scanner on its own demo phishing page, served locally for the check."""
    root = config.ROOT / "demo-sites"
    if not root.exists():
        return "SKIP", "demo-sites folder not present", ""
    if not config.get("SEMGREP_BIN") and not _on_path("semgrep"):
        return "SKIP", "Semgrep not found; set SEMGREP_BIN", ""

    class Quiet(SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    handler = lambda *a, **k: Quiet(*a, directory=str(root), **k)   # noqa: E731
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    os.environ["BRAIN_ALLOW_PRIVATE"] = "1"
    try:
        from brain.pipeline import process_event
        url = f"http://127.0.0.1:{server.server_address[1]}/phish/"
        event, findings = process_event({"event_id": "live-check", "target_url": url, "timestamp": now_iso()})
    finally:
        server.shutdown()
        server.server_close()
    rules = sorted({f.rule for f in findings})
    ok = event["action_status"] == "VERIFIED"
    return ("OK" if ok else "FAIL",
            f"{event['action_status']} at {event['confidence_score']}, rules: {', '.join(rules) or 'none'}", "")


def _on_path(name: str) -> bool:
    from shutil import which
    return which(name) is not None


def check_urlscan(full: bool):
    key = config.get("URLSCAN_API_KEY")
    if not key:
        return "SKIP", "URLSCAN_API_KEY not set", ""
    quota = requests.get("https://urlscan.io/user/quotas/", headers={"API-Key": key}, timeout=15)
    if quota.status_code != 200:
        return "FAIL", f"key rejected, HTTP {quota.status_code}", ""
    day = quota.json().get("limits", {}).get("public", {}).get("day", {})
    detail = f"key accepted, {day.get('used')}/{day.get('limit')} public scans used today"
    target = config.get("CONTROLLED_URL")
    if not full or not target:
        return "OK", detail + ("" if target else "; no CONTROLLED_URL to scan"), ""
    response = requests.post("https://urlscan.io/api/v1/scan/", timeout=20,
                             headers={"API-Key": key, "Content-Type": "application/json"},
                             json={"url": target, "visibility": "public", "tags": ["takedown-orchestrator", "self-test"]})
    if response.status_code != 200:
        return "FAIL", f"submit HTTP {response.status_code}: {response.text[:100]}", ""
    return "OK", "public scan of the controlled target queued", response.json().get("result", "")


def check_netcraft():
    email = config.get("REPORTER_EMAIL")
    if not email:
        return "SKIP", "REPORTER_EMAIL not set", ""
    # Netcraft's development endpoint accepts the same request and files nothing.
    url = config.get("NETCRAFT_REPORT_URL").replace("/api/v3/report/", "/api/v3/test/report/")
    response = requests.post(url, timeout=20, json={"email": email, "urls": [
        {"url": "https://example.invalid/self-test", "reason": "self-test against the development endpoint"}]})
    return ("OK" if response.status_code == 200 else "FAIL",
            f"development endpoint HTTP {response.status_code}: {response.text[:90]}", "")


def check_mail_sink():
    host, port = config.get("SMTP_HOST", "localhost"), int(config.get("SMTP_PORT", "1025"))
    message = EmailMessage()
    message["From"], message["To"] = "self-test@takedown.test", "sink@takedown.test"
    message["Subject"] = "Live check"
    message.set_content("Self-test of the mail sink.")
    try:
        with smtplib.SMTP(host, port, timeout=5) as smtp:
            smtp.send_message(message)
    except OSError:
        return "SKIP", f"no mail sink on {host}:{port}; abuse mails are saved to outbox/ instead", ""
    return "OK", "test mail delivered to the sink", f"http://{host}:8025"


def check_feed(full: bool):
    repo = feed.repo_dir()
    if not (repo / ".git").exists():
        return "SKIP", f"feed repo not cloned at {repo}", ""
    remote = subprocess.run(["git", "-C", str(repo), "ls-remote", "--heads", "origin"],
                            capture_output=True, text=True)
    if remote.returncode != 0:
        return "FAIL", "feed remote not reachable", ""
    if not full:
        return "OK", "feed remote reachable", feed.proof_url(repo, "README").rsplit("/incidents/", 1)[0]
    stamp = datetime.now(timezone.utc).strftime("%H%M%S")
    verdict = Verdict.from_dict({
        "event_id": f"selftest-{stamp}", "target_url": f"https://selftest-{stamp}.invalid/",
        "timestamp": now_iso(), "semgrep_detected": True, "confidence_score": 0.99,
        "evidence": "Self-test entry. The .invalid name can never resolve.", "threat_type": "self-test"})
    enrichment = Enrichment(domain=verdict.host)
    bundle = evidence.build(verdict, enrichment)
    ctx = Context(verdict, enrichment, bundle, evidence.digest(bundle), "public-feed", policy_module.load(), "feed")
    published = feed.execute(ctx)
    if published.status != "SENT":
        return "FAIL", published.detail, ""
    resolved = feed.resolve(verdict.event_id)
    return ("OK" if resolved.status == "SENT" else "FAIL",
            "self-test entry pushed, then resolved and removed from the blocklist", published.proof_url)


def check_controlled_target(full: bool):
    base = config.get("CONTROLLED_URL").rstrip("/")
    if not base:
        return "SKIP", "CONTROLLED_URL not set (the test page hosted on Akash)", ""
    root = base.rsplit("/site", 1)[0]
    page = requests.get(base + "/", timeout=15)
    if not full:
        return ("OK" if page.status_code == 200 else "FAIL"), f"page answers HTTP {page.status_code}", base
    requests.post(root + "/reset", timeout=15)
    ticket = requests.post(root + "/abuse", timeout=15, json={
        "url": base, "event_id": "live-check", "evidence_sha256": "0" * 64})
    after = requests.get(base + "/", timeout=15).status_code
    requests.post(root + "/reset", timeout=15)
    restored = requests.get(base + "/", timeout=15).status_code
    ok = ticket.status_code == 200 and after == 410 and restored == 200
    return ("OK" if ok else "FAIL",
            f"report filed (HTTP {ticket.status_code}), page went {after}, restored to {restored}", base)


def run(full: bool) -> list:
    checks = [
        ("clickhouse write", "ClickHouse", check_clickhouse_write),
        ("clickhouse lookup", "ClickHouse", check_clickhouse_lookup),
        ("scanner", "Semgrep", check_scanner),
        ("urlscan", "urlscan.io", lambda: check_urlscan(full)),
        ("netcraft", "Netcraft", check_netcraft),
        ("feed", "GitHub", lambda: check_feed(full)),
        ("controlled target", "Akash", lambda: check_controlled_target(full)),
        ("mail sink", "local", check_mail_sink),
    ]
    results = []
    for channel, provider, function in checks:
        status, latency, detail, proof = _timed(function)
        results.append({"channel": channel, "provider": provider, "status": status,
                        "latency_ms": latency, "detail": detail, "proof_url": proof})
        print(f"  [{status:<4}] {channel:<18} {provider:<11} {latency:>6} ms  {detail}"
              + (f"  -> {proof}" if proof else ""))
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--full", action="store_true", help="also run the checks that leave a trace")
    args = parser.parse_args()
    print("LIVE CHECK, full" if args.full else "LIVE CHECK, read-only")
    results = run(args.full)
    record = {"ts": now_iso(), "full": args.full, "checks": results}
    OUT.write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    client = clickhouse_client()
    if client is not None:
        now = datetime.now(timezone.utc)
        client.insert("live_checks", [[now, r["channel"], r["provider"], r["status"], r["latency_ms"],
                                       r["detail"], r["proof_url"]] for r in results],
                      column_names=["checked_at", "channel", "provider", "status", "latency_ms", "detail", "proof_url"])
    sys.exit(1 if any(r["status"] == "FAIL" for r in results) else 0)


if __name__ == "__main__":
    main()
