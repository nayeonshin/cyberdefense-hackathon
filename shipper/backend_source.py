"""Read-only projection of Members 1–3's native ClickHouse tables.

No DDL, migrations, scanning, dispatch, or target requests happen here. In
particular, an Actor update timestamp must not masquerade as a scan timestamp.
"""
import os

from .data import clickhouse_client, identifier
from .model import parse_time, validate_event

COMPLETE = ("VERIFIED", "REJECTED", "PUBLISHED_TAKEDOWN", "WITHHELD", "TAKEN_DOWN")
COMPLETE_SQL = "('VERIFIED','REJECTED','PUBLISHED_TAKEDOWN','WITHHELD','TAKEN_DOWN')"


class BackendSource:
    simulated = False

    def __init__(self, settings, client=None):
        self.settings = settings
        self.client = client or clickhouse_client()
        self.threats = identifier(os.getenv("THREATS_TABLE", "incoming_threats"))
        self.verdicts = identifier(os.getenv("VERDICTS_TABLE", "events"))
        self.actions = identifier(os.getenv("ACTIONS_TABLE", "actions"))

    def _query(self, sql, parameters=None):
        return list(self.client.query(sql, parameters=parameters).named_results())

    def _exists(self, table):
        return bool(self.client.query(f"EXISTS TABLE {table}").first_row[0])

    def get_events(self):
        raw = self._query(f"""SELECT event_id, argMax(target_url, first_seen) AS target_url,
            argMax(timestamp, first_seen) AS event_time, min(first_seen) AS ingested_at
            FROM {self.threats} GROUP BY event_id ORDER BY ingested_at DESC, event_id LIMIT 200""")
        verdicts = []
        if raw and self._exists(self.verdicts):
            verdicts = self._query(f"SELECT * FROM {self.verdicts} FINAL "
                "WHERE event_id IN {ids:Array(String)}", {"ids": [r["event_id"] for r in raw]})
        by_target = {(v["event_id"], v["target_url"]): v for v in verdicts}
        result = []
        for row in raw:
            verdict = by_target.get((row["event_id"], row["target_url"]), {})
            status = verdict.get("action_status") or "PENDING"
            completed = status in COMPLETE and verdict.get("semgrep_detected") is not None
            failed = status in {"FETCH_FAILED", "SCAN_FAILED"}
            # Nullable pending values become strict contract defaults only in this
            # projection; completion stays explicit in presentation metadata.
            event = {"event_id": row["event_id"], "target_url": row["target_url"],
                     "timestamp": parse_time(row["event_time"]).isoformat(),
                     "semgrep_detected": bool(verdict.get("semgrep_detected")),
                     "confidence_score": float(verdict.get("confidence_score") or 0),
                     "evidence": verdict.get("evidence") or "", "action_status": status,
                     "proof_url": verdict.get("proof_url") or ""}
            # ReplacingMergeTree can discard the original scanner version after
            # the Actor appends an outcome. Keep that timestamp unknown.
            scan_time = verdict.get("updated_at") if completed and status in {"VERIFIED", "REJECTED"} else None
            result.append({"event": validate_event(event), "metadata": {
                "ingested_at": row["ingested_at"], "scan_completed": completed,
                "scan_completed_at": scan_time, "scanner": "semgrep" if completed else "",
                "scan_error": status if failed else "",
                "scan_time_basis": "Scanner verdict persisted" if scan_time else "Not recorded",
                "source": "backend", "run_id": None}})
        return result

    def get_receipts(self, event_id=None):
        if not self._exists(self.actions):
            return []
        where = f"(event_id, target_url) IN (SELECT event_id, target_url FROM {self.threats})"
        params = None
        if event_id is not None:
            where += " AND event_id={event:String}"
            params = {"event": event_id}
        rows = self._query(f"SELECT * FROM {self.actions} WHERE {where} "
                           "ORDER BY created_at DESC LIMIT 500", params)
        for row in rows:
            row["created_at"] = parse_time(row["created_at"]).isoformat()
        return rows

    def get_metrics(self):
        # Aggregate over the whole raw table, not just the 200-row UI window.
        raw = (f"SELECT event_id, argMax(target_url, first_seen) AS target_url, "
               f"min(first_seen) AS ingested_at FROM {self.threats} GROUP BY event_id")
        has_verdicts = self._exists(self.verdicts)
        complete = f"v.action_status IN {COMPLETE_SQL} AND v.semgrep_detected IS NOT NULL" if has_verdicts else "0"
        detected = f"({complete}) AND v.semgrep_detected = 1" if has_verdicts else "0"
        join = (f"LEFT JOIN (SELECT * FROM {self.verdicts} FINAL) AS v "
                "ON r.event_id=v.event_id AND r.target_url=v.target_url") if has_verdicts else ""
        values = self._query(f"SELECT count() AS total_events, "
            "countIf(r.ingested_at >= now() - INTERVAL 1 MINUTE AND r.ingested_at <= now()) AS ingested_per_minute, "
            f"countIf(NOT ({complete})) AS pending_scans, countIf({detected}) AS detected "
            f"FROM ({raw}) AS r {join}")[0]
        submitted = 0
        if self._exists(self.actions):
            submitted = self._query(f"SELECT count() AS submitted_actions FROM {self.actions} "
                "WHERE status='SENT' AND NOT dry_run AND (event_id,target_url) IN "
                f"(SELECT event_id,target_url FROM {self.threats})")[0]["submitted_actions"]
        return {**values, "submitted_actions": submitted}

    def close(self):
        self.client.close()
