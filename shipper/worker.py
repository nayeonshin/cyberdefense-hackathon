"""The only process allowed to call the Actor. No Streamlit imports."""
import hashlib
import json
import os
import signal
import threading
import time
from datetime import datetime, timezone

from filelock import FileLock
from actor import config
from actor.dispatch import dispatch
from actor.contract import Verdict
from actor.ledger import COLUMNS, DDL, Ledger, _parse
from actor.recheck import recheck_once
from .controlled import start_registrar
from .data import make_source
from .model import now_iso, parse_time
from .settings import Settings
from .storage import read_json, write_json

LIVE_FLAGS = ("LIVE_FEED", "LIVE_URLSCAN", "LIVE_NETCRAFT", "LIVE_ABUSEIPDB", "LIVE_EMAIL")


class DurableLedger(Ledger):
    def __init__(self, run_dir):
        super().__init__(run_dir / "actions.jsonl", use_clickhouse=False)
        self.synced_path = run_dir / "synced.json"

    def save_state(self, state):
        write_json(self.state_path, state)

    def flush(self, client):
        """Retry unsynced local receipts, checking identity before insertion."""
        client.command(DDL)
        synced = set(read_json(self.synced_path, []))
        for row in self.all():
            key = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
            if key in synced:
                continue
            timestamp = _parse(row["created_at"])
            existing = client.query("SELECT count() FROM actions WHERE event_id={event:String} "
                "AND action={action:String} AND status={status:String} AND created_at={time:DateTime64(3, 'UTC')} "
                "AND evidence_sha256={sha:String}", parameters={"event": row["event_id"], "action": row["action"],
                "status": row["status"], "time": timestamp, "sha": row["evidence_sha256"]}).first_row[0]
            if not existing:
                values = [row[c] for c in COLUMNS]
                values[-1] = timestamp
                client.insert("actions", [values], column_names=COLUMNS)
            synced.add(key)
            write_json(self.synced_path, sorted(synced))


class Coordinator:
    def __init__(self, settings, source, ledger=None):
        self.settings, self.source = settings, source
        self.ledger = ledger or DurableLedger(settings.run_dir)
        self.attempts_path = settings.run_dir / "attempts.json"
        self.attempts = read_json(self.attempts_path, {})
        self.last_recheck = 0
        self.started_at = now_iso()

    def heartbeat(self, status, detail="", **extra):
        write_json(self.settings.run_dir / "heartbeat.json", {"status": status, "detail": detail,
                   "updated_at": now_iso(), "started_at": self.started_at, "run_id": self.settings.run_id,
                   "mode": self.settings.mode, "source": self.settings.source, **extra})

    def recover_recheck(self, event):
        """Close the crash window between a saved receipt and Actor state."""
        rows = [r for r in self.ledger.all() if r["event_id"] == event["event_id"]
                and r["target_url"] == event["target_url"] and not r["dry_run"]]
        if not any(r["action"] == "mock_registrar" and r["status"] == "SENT" for r in rows):
            return
        state = self.ledger.load_state()
        entry = state.get(event["event_id"])
        changed = entry is None
        if entry is None:
            entry = {"verdict": Verdict.from_dict({**event, "controlled": True, "simulated": False}).__dict__,
                     "fails": 0, "confirmed": False, "escalated": False}
            state[event["event_id"]] = entry
        if not entry["confirmed"] and any(r["status"] == "CONFIRMED_DOWN" for r in rows):
            entry["confirmed"], changed = True, True
        if changed:
            self.ledger.save_state(state)

    def tick(self):
        if self.settings.mode == "preview":
            self.heartbeat("preview", "Preview only. No actions are executed.")
            return
        if config.kill_switch():
            self.heartbeat("paused", "Actor stop switch is active.")
            return
        if hasattr(self.source, "client"):
            self.ledger.flush(self.source.client)
        records = self.source.get_events()
        eligible = 0
        for record in records:
            event, meta = record["event"], record["metadata"]
            if (event["target_url"] != self.settings.controlled_url or meta.get("run_id") != self.settings.run_id
                or meta.get("scanner") != "semgrep" or not meta.get("scan_completed_at")
                or meta.get("scan_error") or event["action_status"] in {"SCAN_FAILED", "FETCH_FAILED"}
                or not event["semgrep_detected"] or not event["evidence"]):
                continue
            parse_time(meta["scan_completed_at"])
            eligible += 1
            self.recover_recheck(event)
            event_id = event["event_id"]
            previous = self.attempts.get(event_id, {})
            if previous.get("complete") or previous.get("count", 0) >= 3:
                continue
            if time.time() < previous.get("next_at", 0):
                continue
            # The private registrar is idempotent by event + evidence. Actor domain-level
            # dedupe remains authoritative, including when this run is restarted.
            attempt = {"count": previous.get("count", 0) + 1, "next_at": time.time() + 15}
            self.attempts[event_id] = attempt
            write_json(self.attempts_path, self.attempts)
            verdict = {**event, "controlled": True, "simulated": False}
            receipts = dispatch(verdict, live=True, offline=True, ledger=self.ledger)
            if any(r.status == "SENT" and r.action == "mock_registrar" for r in receipts):
                attempt["complete"] = True
            elif "mock_registrar" in self.ledger.done_actions("localhost"):
                attempt["complete"] = True
            write_json(self.attempts_path, self.attempts)
        if time.monotonic() - self.last_recheck >= self.settings.recheck_seconds:
            recheck_once(ledger=self.ledger, live=True)
            self.last_recheck = time.monotonic()
            # Explicit fresh check after restart; historical confirmations stay historical
            # until this succeeds, even if the Actor's state says it was confirmed earlier.
            import requests
            response = requests.head(self.settings.controlled_url, timeout=3, allow_redirects=False)
            write_json(self.settings.run_dir / "target-check.json", {"checked_at": now_iso(),
                "started_at": self.started_at, "http_status": response.status_code,
                "controlled": True, "suspended": response.status_code == 410})
        if hasattr(self.source, "client"):
            self.ledger.flush(self.source.client)
        exhausted = sum(v.get("count", 0) >= 3 and not v.get("complete") for v in self.attempts.values())
        self.heartbeat("degraded" if exhausted else "running" if eligible else "waiting",
            f"{exhausted} event(s) exhausted bounded retries; inspect receipts." if exhausted
            else "Controlled target only; external reporting disabled." if eligible
            else "Waiting for a completed Semgrep verdict from Member 2.")


def main():
    settings = Settings.from_env()
    settings.run_dir.mkdir(parents=True, exist_ok=True)
    os.environ["OUTBOX_DIR"] = str(settings.run_dir / "outbox")
    if settings.mode == "controlled":
        for name in LIVE_FLAGS:
            os.environ[name] = "0"
        os.environ["MOCK_REGISTRAR_URL"] = "http://localhost:8099"
    stop = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stop.set())
    with FileLock(str(settings.data_dir / "coordinator.lock"), timeout=0):
        server = start_registrar(settings.run_dir) if settings.mode == "controlled" else None
        source = None
        coordinator = None
        try:
            while not stop.is_set():
                try:
                    if source is None:
                        source = make_source(settings)
                        coordinator = Coordinator(settings, source)
                    coordinator.tick()
                except Exception as exc:
                    # Never persist exception messages: drivers may include credentials or queries.
                    status = {"status": "degraded", "detail": f"{type(exc).__name__}: integration unavailable; see local service logs.",
                              "updated_at": now_iso(), "started_at": coordinator.started_at if coordinator else now_iso(),
                              "run_id": settings.run_id, "mode": settings.mode, "source": settings.source}
                    try:
                        write_json(settings.run_dir / "heartbeat.json", status)
                    except PermissionError:
                        print("Worker heartbeat temporarily locked; next cycle will retry.", flush=True)
                    print(f"worker: {type(exc).__name__}; retrying without fixture fallback", flush=True)
                stop.wait(settings.poll_seconds)
        finally:
            if coordinator:
                coordinator.heartbeat("stopped", "Worker shut down.")
            if server:
                server.shutdown()
                server.server_close()
            if source and hasattr(source, "close"):
                source.close()


if __name__ == "__main__":
    main()
