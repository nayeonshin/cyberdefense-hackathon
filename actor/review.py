"""Build a page for checking the Actor's decisions by eye.

    python -m actor.review            writes actor/bench/review.html from the last stress run
    python -m actor.review --restyle  applies bench/review_template.html again, without the database

The page shows one decision at a time: what the scanner said about a URL, what was on
record, and what the Actor did about it. Mark each one right or wrong with a key; the
wrong ones are collected as text to hand back.
"""
import json
import re
import sys
from html import escape
from pathlib import Path

from . import history, policy as policy_module
from .contract import safe_id
from .evidence import defang
from .ledger import clickhouse_client

OUT = Path(__file__).parent / "bench" / "review.html"
TEMPLATE = Path(__file__).parent / "bench" / "review_template.html"
PER_GROUP = 12
SENT = ("SENT", "SINK")

GROUPS = [
    ("hostile", "Hostile input", "A row no scanner should produce. Nothing may be done against the target named in it."),
    ("platform", "Shared platform", "A bad page on a platform many others use. Report the URL; never block or mail the platform."),
    ("full", "Mail to the host", "High confidence and a second source. The hosting provider gets an abuse report."),
    ("report", "Report only", "High confidence without a second source. Reporting platforms, no mail."),
    ("protect", "Feed only", "Confidence between 0.80 and 0.90. Published to the feed and nothing more."),
    ("low", "Too uncertain", "Confidence below 0.80. Nothing happens."),
    ("untouched", "Not verified", "The scanner rejected the page or could not fetch it. The Actor must not touch it."),
]


def collect(client) -> list:
    policy = policy_module.load()
    events = client.query(
        "SELECT event_id, target_url, action_status, proof_url, confidence_score, semgrep_detected "
        "FROM stress_events FINAL").named_results()
    feeds = dict(client.query("SELECT event_id, any(feed_source) FROM stress_threats GROUP BY event_id").result_rows)
    receipts = {}
    for row in client.query(
            "SELECT event_id, action, recipient, status, dry_run, detail, proof_url FROM stress_actions "
            "ORDER BY created_at").named_results():
        receipts.setdefault(row["event_id"], []).append(row)
    events = list(events)
    hosts = sorted({history._host(e["target_url"]) for e in events} - {""})
    on_record = {}
    for start in range(0, len(hosts), 2000):
        on_record.update(dict(client.query(
            "SELECT host, count() FROM threat_history WHERE host IN {hosts:Array(String)} GROUP BY host",
            parameters={"hosts": hosts[start:start + 2000]}).result_rows))

    cases = []
    for e in events:
        event_id, url = e["event_id"], e["target_url"]
        host = history._host(url)
        mine = receipts.get(event_id) or receipts.get(safe_id(event_id)) or []
        sent = [r for r in mine if r["status"] in SENT and not r["dry_run"]]
        actions = sorted({r["action"] for r in sent})
        confidence = e["confidence_score"]
        platform = bool(host) and policy_module.is_allowlisted(host, policy)
        if e["action_status"] in ("REJECTED", "FETCH_FAILED"):
            group = "untouched"
        elif event_id.startswith("hostile-") or event_id.startswith("..") or event_id == "dup-event":
            group = "hostile"
        elif platform:
            group = "platform"
        elif confidence is None or confidence < 0.80:
            group = "low"
        elif confidence < 0.90:
            group = "protect"
        elif "notify_host" in actions:
            group = "full"
        else:
            group = "report"
        shown = defang(url)
        cases.append({
            "id": event_id, "group": group,
            "url": shown[:220] + (f" ... ({len(url):,} characters)" if len(shown) > 220 else ""),
            "host": defang(host)[:120],
            "scanner": "VERIFIED" if group != "untouched" else e["action_status"],
            "detected": e["semgrep_detected"], "confidence": None if confidence is None else round(confidence, 2),
            "feed": feeds.get(event_id, ""), "on_record": int(on_record.get(host, 0)),
            "platform": platform, "outcome": e["action_status"],
            "sent": [{"action": r["action"], "to": defang(r["recipient"])[:80],
                      "how": "mail sink" if r["status"] == "SINK" else "recorded"} for r in sent],
            "held": [{"action": r["action"], "why": defang(r["detail"])[:200]}
                     for r in mine if r["status"] == "SKIPPED"],
        })
    return cases


def sample(cases: list) -> list:
    """Every hostile row, and the same number of each other kind, in a fixed order."""
    picked = []
    for key, _, _ in GROUPS:
        mine = sorted((c for c in cases if c["group"] == key), key=lambda c: c["id"])
        picked += mine if key == "hostile" else mine[:PER_GROUP]
    return picked


def render(picked: list, total: int) -> None:
    summary = (f"{len(picked)} decisions out of {total:,} from the last stress run on ClickHouse: "
               f"every hostile row and {PER_GROUP} of each other kind.")
    data = json.dumps(picked, ensure_ascii=True).replace("</", "<\\/")
    groups = json.dumps({key: [title, note] for key, title, note in GROUPS})
    page = (TEMPLATE.read_text(encoding="utf-8").replace("__SUMMARY__", escape(summary))
            .replace("__CASES__", data).replace("__GROUPS__", groups).replace("__RUN__", str(total)))
    OUT.write_text(page, encoding="utf-8")


def restyle() -> None:
    """Apply the template again to the cases already in review.html, without the database."""
    old = OUT.read_text(encoding="utf-8")
    picked = json.loads(re.search(r"const CASES = (\[.*?\]);\nconst GROUPS", old, re.S).group(1))
    total = int(re.search(r'const KEY = "actor-review-(\d+)"', old).group(1))
    render(picked, total)
    print(f"{OUT.name}: restyled, {len(picked)} cases")


def main() -> None:
    if "--restyle" in sys.argv:
        return restyle()
    client = clickhouse_client()
    if client is None:
        sys.exit("CLICKHOUSE_HOST and CLICKHOUSE_PASSWORD must be set in .env")
    cases = collect(client)
    if not cases:
        sys.exit("stress_events is empty; run `python -m actor.stress` first")
    picked = sample(cases)
    counts = {key: sum(1 for c in cases if c["group"] == key) for key, _, _ in GROUPS}
    render(picked, len(cases))
    print(f"{OUT.name}: {len(picked)} cases to review, from {len(cases)} events")
    for key, title, _ in GROUPS:
        print(f"  {title:<18} {counts[key]:>5} in the run")


if __name__ == "__main__":
    main()
