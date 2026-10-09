"""Rungs 3 and 4: is the target still up? Escalate if so, confirm when it is gone.

    python -m actor.recheck --live                 one pass
    python -m actor.recheck --live --loop          keep checking
"""
import argparse
import time
from datetime import datetime, timezone

import requests

from . import config, policy as policy_module
from .actions import feed
from .contract import Receipt, Verdict
from .dispatch import print_receipts, run_plans
from .enrich import enrich, is_ip, resolve
from .ledger import Ledger

DOWN_CODES = (404, 410, 451)


def probe(url: str, host: str) -> tuple:
    """(is_up, reason). Uses HEAD, so no page content is downloaded."""
    if not is_ip(host) and host != "localhost" and not resolve(host):
        return False, "domain no longer resolves"
    try:
        response = requests.head(url, timeout=8, allow_redirects=False)
    except requests.RequestException as exc:
        return False, f"no connection ({type(exc).__name__})"
    if response.status_code in DOWN_CODES or response.status_code >= 500:
        return False, f"HTTP {response.status_code}"
    return True, f"HTTP {response.status_code}"


def recheck_once(ledger: Ledger = None, policy: dict = None, live: bool = False) -> list:
    ledger = ledger or Ledger()
    policy = policy or policy_module.load()
    rules = policy["recheck"]
    state = ledger.load_state()
    receipts = []
    for event_id, entry in state.items():
        if entry["confirmed"]:
            continue
        verdict = Verdict.from_dict(entry["verdict"])
        up, reason = probe(verdict.target_url, verdict.host)
        first = ledger.first_action_at(event_id)
        elapsed = (datetime.now(timezone.utc) - first).total_seconds() if first else 0

        if not up:
            entry["fails"] += 1
            if entry["fails"] >= rules["confirm_failures"]:
                entry["confirmed"] = True
                detail = f"confirmed down after {int(elapsed)}s: {reason}"
                if live and config.flag("LIVE_FEED"):
                    detail += "; " + feed.resolve(event_id).detail
                receipt = Receipt(event_id, verdict.target_url, verdict.host, "confirm", 4, "",
                                  "CONFIRMED_DOWN", dry_run=not live,
                                  latency_ms=int(elapsed * 1000), detail=detail)
                ledger.append(receipt)
                receipts.append(receipt)
            continue

        entry["fails"] = 0
        if elapsed >= rules["escalate_after_seconds"] and not entry["escalated"]:
            entry["escalated"] = True
            enrichment = enrich(verdict.host)
            decision = policy_module.escalation(
                verdict, enrichment, policy, ledger.done_actions(verdict.host))
            still_up = Receipt(event_id, verdict.target_url, verdict.host, "recheck", 3, "",
                               "STILL_UP", dry_run=not live,
                               detail=f"still up after {int(elapsed)}s ({reason})")
            ledger.append(still_up)
            receipts.append(still_up)
            receipts += run_plans(verdict, enrichment, decision.plans, live, ledger, policy)
    ledger.save_state(state)
    return receipts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--interval", type=int, default=30)
    args = parser.parse_args()
    while True:
        receipts = recheck_once(live=args.live)
        print_receipts(receipts) if receipts else print("no change")
        if not args.loop:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
