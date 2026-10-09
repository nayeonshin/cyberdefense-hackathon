"""One run of the on-stage loop: bring the controlled page back, report it, watch it go down.

    python -m actor.stage             a new event id every time
    python -m actor.stage my-id       a chosen id (must not have been used before)

Start these first, each in its own terminal:

    python -m actor.mock_registrar_server
    python -m brain.worker --interval 3
    python -m actor.intake --live --loop --interval 5

This inserts one row for the controlled target into Member 1's table and prints each change
of the event with the seconds since the insert. It touches nothing else.
"""
import sys
import time
from datetime import datetime, timezone

import requests

from . import config
from .intake import events_table, verdicts_table
from .ledger import clickhouse_client

STEPS = ["VERIFIED", "PUBLISHED_TAKEDOWN", "TAKEN_DOWN"]
STOPPED = ["REJECTED", "FETCH_FAILED", "WITHHELD"]
WAIT = 180


def main() -> None:
    base = (config.get("MOCK_REGISTRAR_URL") or "http://localhost:8099").rstrip("/")
    target = config.get("CONTROLLED_URL") or base + "/site/"
    event_id = sys.argv[1] if len(sys.argv) > 1 else datetime.now(timezone.utc).strftime("stage-%H%M%S")
    client = clickhouse_client()
    if client is None:
        sys.exit("CLICKHOUSE_HOST and CLICKHOUSE_PASSWORD must be set in .env")
    used = client.query(f"SELECT count() FROM {events_table()} WHERE event_id = {{id:String}}",
                        parameters={"id": event_id}).result_rows[0][0]
    if used:
        sys.exit(f"{event_id} was used before; a finished id is not scanned again. Pick a new one.")
    try:
        requests.post(base + "/reset", timeout=5)
        up = requests.get(target, timeout=5).status_code
    except requests.RequestException as exc:
        sys.exit(f"the controlled target does not answer at {base}: {type(exc).__name__}. "
                 "Start `python -m actor.mock_registrar_server` first.")
    print(f"target {target} is up (HTTP {up})")

    client.command(
        f"INSERT INTO {events_table()} (event_id, target_url, domain, ip_address, `timestamp`, threat_type, "
        "takedown_status, feed_source) VALUES ({id:String}, {url:String}, 'localhost', '127.0.0.1', now(), "
        "'phishing', 'PENDING', 'controlled-demo')", parameters={"id": event_id, "url": target})
    started = time.perf_counter()
    print(f"   0.0 s  {event_id} reported to the pipeline")
    seen = None
    while time.perf_counter() - started < WAIT:
        rows = client.query(
            f"SELECT action_status, proof_url, confidence_score FROM {verdicts_table()} FINAL "
            "WHERE event_id = {id:String}", parameters={"id": event_id}).result_rows
        if rows and rows[0][0] != seen:
            seen, proof, confidence = rows[0]
            extra = f"  confidence {confidence:.2f}" if seen == "VERIFIED" and confidence is not None else ""
            extra += f"  {proof}" if proof and seen != "VERIFIED" else ""
            print(f"{time.perf_counter() - started:6.1f} s  {seen}{extra}")
            if seen == STEPS[-1] or seen in STOPPED:
                break
        time.sleep(0.5)
    else:
        print(f"no further change after {WAIT} s; last state {seen or 'still pending'}. "
              "Are the worker and the Actor loop running?")
        sys.exit(1)
    try:
        now = requests.get(target, timeout=5).status_code
    except requests.RequestException:
        now = "no answer"
    print(f"target now answers: HTTP {now}")
    sys.exit(0 if seen == STEPS[-1] else 1)


if __name__ == "__main__":
    main()
