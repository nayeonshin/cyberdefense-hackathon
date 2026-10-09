"""The Actor: turn a verified verdict into actions on the open web, with receipts.

    python -m actor.dispatch fixtures/verdicts.json            plan only (dry run)
    python -m actor.dispatch fixtures/verdicts.json --live     execute enabled channels
    python -m actor.dispatch --poll --live                     follow the ClickHouse table
"""
import argparse
import json
import sys
import time

from . import config, evidence, history, policy as policy_module
from .actions import Context, registry
from .contract import DONE_STATUSES, Receipt, Verdict, safe_id
from .enrich import Enrichment, enrich
from .ledger import Ledger, clickhouse_client

MAIL_ACTIONS = ("notify_host", "notify_registrar")

DEFAULT_QUERY = """
SELECT event_id, target_url, toString(timestamp) AS timestamp, semgrep_detected,
       confidence_score, evidence
FROM incoming_threats
WHERE semgrep_detected
  AND event_id NOT IN (SELECT event_id FROM actions WHERE NOT dry_run)
ORDER BY timestamp
LIMIT 20
"""


def run_plans(verdict: Verdict, enrichment: Enrichment, plans: list, live: bool,
              ledger: Ledger, policy: dict) -> list:
    """Execute (or only plan) each action and write one receipt per action."""
    bundle = evidence.build(verdict, enrichment, history.lookup(verdict.host))
    sha = evidence.digest(bundle)
    modules = registry()
    limit = policy["rate_limit_per_recipient_per_hour"]
    # Mail about the team's own target only ever reaches the sink, so rehearsals are not counted.
    controlled = policy_module.is_controlled(verdict, policy)
    receipts = []
    for plan in plans:
        module = modules[plan.action]
        ctx = Context(verdict, enrichment, bundle, sha, plan.recipient, policy, plan.action)
        receipt = Receipt(verdict.event_id, verdict.target_url, verdict.host, plan.action,
                          plan.rung, plan.recipient, "PLANNED", evidence_sha256=sha,
                          detail=module.describe(ctx))
        if config.kill_switch():
            receipt.status, receipt.detail = "SKIPPED", "kill switch is on"
        elif not live:
            pass
        elif verdict.simulated:
            receipt.detail = "simulated verdict, never sent: " + receipt.detail
        elif module.LIVE_FLAG and not config.flag(module.LIVE_FLAG):
            receipt.detail = f"channel off ({module.LIVE_FLAG}=0): " + receipt.detail
        elif plan.action in MAIL_ACTIONS and not controlled and ledger.count_recent(plan.recipient) >= limit:
            receipt.status = "SKIPPED"
            receipt.detail = f"rate limit of {limit} mails per hour reached for {plan.recipient}"
        elif plan.action == "abuseipdb" and ledger.reported(plan.action, plan.recipient, verdict.host):
            receipt.status, receipt.detail = "SKIPPED", f"{plan.recipient} was already reported"
        else:
            started = time.perf_counter()
            try:
                outcome = module.execute(ctx)
                receipt.status, receipt.proof_url = outcome.status, outcome.proof_url
                receipt.detail = outcome.detail
            except Exception as exc:
                receipt.status, receipt.detail = "FAILED", f"{type(exc).__name__}: {exc}"
            receipt.latency_ms = int((time.perf_counter() - started) * 1000)
            receipt.dry_run = False
        ledger.append(receipt)
        receipts.append(receipt)
    return receipts


def dispatch(verdict, live: bool = False, offline: bool = False,
             ledger: Ledger = None, policy: dict = None) -> list:
    """Run the ladder for one verdict (a dict in the team contract, or a Verdict)."""
    ledger = ledger or Ledger()
    if not isinstance(verdict, Verdict):
        try:
            verdict = Verdict.from_dict(verdict)
        except ValueError as exc:
            claimed = verdict.get("event_id", "invalid") if isinstance(verdict, dict) else "invalid"
            refusal = Receipt(safe_id(claimed), "", "", "all", 0, "", "SKIPPED", dry_run=not live,
                              detail=f"malformed verdict refused: {exc}")
            ledger.append(refusal)
            return [refusal]
    policy = policy or policy_module.load()
    controlled = policy_module.is_controlled(verdict, policy)
    enrichment = enrich(verdict.host, offline=offline or controlled)
    # A query on the history table can stand in for the second source: enough malicious
    # URLs already on record for this host and the Actor may notify the hosting provider.
    record = None if controlled else history.lookup(verdict.host)
    if record and record["urls_on_record"] >= policy["history"]["corroborates_at"]:
        verdict.corroborated = True
    if not live:
        done = frozenset()
    elif policy_module.is_allowlisted(verdict.host, policy):
        done = ledger.done_for_url(verdict.target_url)
    else:
        done = ledger.done_actions(verdict.host)
    decision = policy_module.decide(verdict, enrichment, policy, done)

    receipts = run_plans(verdict, enrichment, decision.plans, live, ledger, policy)
    for action, reason in decision.skipped:
        receipt = Receipt(verdict.event_id, verdict.target_url, verdict.host, action, 0, "",
                          "SKIPPED", dry_run=not live, detail=reason)
        ledger.append(receipt)
        receipts.append(receipt)

    if live and any(r.status in DONE_STATUSES for r in receipts):
        state = ledger.load_state()
        state.setdefault(verdict.event_id, {
            "verdict": verdict.__dict__, "fails": 0, "confirmed": False, "escalated": False})
        ledger.save_state(state)
    return receipts


def print_receipts(receipts: list) -> None:
    for r in receipts:
        proof = f"  -> {r.proof_url}" if r.proof_url else ""
        print(f"  [{r.status:<8}] rung {r.rung} {r.action:<16} {r.detail}{proof}")


def fetch_pending(client) -> list:
    query = config.get("VERDICTS_QUERY") or DEFAULT_QUERY
    return list(client.query(query).named_results())


def poll(live: bool, interval: int) -> None:
    client = clickhouse_client()
    if client is None:
        sys.exit("CLICKHOUSE_HOST is not set; add it to .env")
    ledger, seen = Ledger(), set()
    print(f"polling every {interval}s, {'LIVE' if live else 'dry run'}; Ctrl+C to stop")
    while True:
        for row in fetch_pending(client):
            if row["event_id"] in seen:
                continue
            seen.add(row["event_id"])
            print(f"{row['event_id']}  {row['target_url']}")
            print_receipts(dispatch(row, live=live, ledger=ledger))
        time.sleep(interval)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("file", nargs="?", help="JSON file with one verdict or a list")
    parser.add_argument("--live", action="store_true", help="execute enabled channels")
    parser.add_argument("--offline", action="store_true", help="skip DNS and RDAP lookups")
    parser.add_argument("--poll", action="store_true", help="follow the ClickHouse table")
    parser.add_argument("--interval", type=int, default=10)
    args = parser.parse_args()

    if args.poll:
        poll(args.live, args.interval)
        return
    if not args.file:
        parser.error("give a verdict file or --poll")
    with open(args.file, encoding="utf-8") as handle:
        data = json.load(handle)
    ledger = Ledger()
    print("LIVE: enabled channels will send" if args.live else "DRY RUN: nothing is sent")
    for item in data if isinstance(data, list) else [data]:
        print(f"{item['event_id']}  {item['target_url']}")
        print_receipts(dispatch(item, live=args.live, offline=args.offline, ledger=ledger))


if __name__ == "__main__":
    main()
