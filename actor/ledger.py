"""Append-only record of every action: a local JSONL file and, when configured, ClickHouse."""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import config
from .contract import DONE_STATUSES, Receipt

DDL = """
CREATE TABLE IF NOT EXISTS actions (
    event_id String,
    target_url String,
    domain String,
    action LowCardinality(String),
    rung UInt8,
    recipient String,
    status LowCardinality(String),
    proof_url String,
    evidence_sha256 String,
    dry_run Bool,
    latency_ms UInt32,
    detail String,
    created_at DateTime64(3, 'UTC')
) ENGINE = MergeTree ORDER BY (created_at, event_id)
"""

COLUMNS = ["event_id", "target_url", "domain", "action", "rung", "recipient", "status",
           "proof_url", "evidence_sha256", "dry_run", "latency_ms", "detail", "created_at"]


def _parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def clickhouse_client():
    """A client when CLICKHOUSE_HOST is set, otherwise None."""
    host = config.get("CLICKHOUSE_HOST")
    if not host or not config.get("CLICKHOUSE_PASSWORD"):
        return None
    import clickhouse_connect
    return clickhouse_connect.get_client(
        host=host,
        port=int(config.get("CLICKHOUSE_PORT", "8443")),
        username=config.get("CLICKHOUSE_USER", "default"),
        password=config.get("CLICKHOUSE_PASSWORD"),
        database=config.get("CLICKHOUSE_DATABASE", "default"),
        secure=True,
    )


class Ledger:
    def __init__(self, path: Path = None, use_clickhouse: bool = True):
        self.path = path or (config.ROOT / "ledger" / "actions.jsonl")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._client = None
        self._rows = None            # loaded on first use, then kept in step by append()
        self._use_clickhouse = use_clickhouse
        self._table_ready = False

    def _clickhouse(self):
        if not self._use_clickhouse:
            return None
        if self._client is None:
            self._client = clickhouse_client()
        if self._client is not None and not self._table_ready:
            self._client.command(DDL)
            self._table_ready = True
        return self._client

    def append(self, receipt: Receipt) -> None:
        row = receipt.to_dict()
        self.all().append(row)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row) + "\n")
        try:
            client = self._clickhouse()
            if client is not None:
                values = [row[c] for c in COLUMNS]
                values[-1] = _parse(row["created_at"])
                client.insert("actions", [values], column_names=COLUMNS)
        except Exception as exc:  # the local file stays the source of truth
            print(f"[ledger] ClickHouse insert failed: {exc}", file=sys.stderr)

    @property
    def state_path(self) -> Path:
        return self.path.with_name("state.json")

    def load_state(self) -> dict:
        """Per-event recheck state: the verdict, failed checks, escalated, confirmed."""
        if not self.state_path.exists():
            return {}
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def save_state(self, state: dict) -> None:
        self.state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")

    def all(self) -> list:
        if self._rows is None:
            self._rows = []
            if self.path.exists():
                with self.path.open(encoding="utf-8") as handle:
                    self._rows = [json.loads(line) for line in handle if line.strip()]
        return self._rows

    def done_actions(self, domain: str) -> frozenset:
        """Actions that really went out for this domain (dry runs do not count)."""
        return frozenset(r["action"] for r in self.all()
                         if r["domain"] == domain and r["status"] in DONE_STATUSES
                         and not r["dry_run"])

    def reported(self, action: str, recipient: str) -> bool:
        return any(r["action"] == action and r["recipient"] == recipient
                   and r["status"] in DONE_STATUSES and not r["dry_run"] for r in self.all())

    def count_recent(self, recipient: str, seconds: int = 3600) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=seconds)
        return sum(1 for r in self.all()
                   if r["recipient"] == recipient and r["status"] in DONE_STATUSES
                   and not r["dry_run"] and _parse(r["created_at"]) >= cutoff)

    def first_action_at(self, event_id: str):
        times = [_parse(r["created_at"]) for r in self.all()
                 if r["event_id"] == event_id and r["status"] in DONE_STATUSES
                 and not r["dry_run"]]
        return min(times) if times else None
