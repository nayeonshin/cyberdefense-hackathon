# Integration handoff

## Owners

| Owner | Required handoff | State |
|---|---|---|
| Member 1 | Ingestion code/schema; reachable ClickHouse connection | Code integrated; instance is localhost-only |
| Member 2 | Scanner, dependencies, real rules, Guild AI run evidence | Python scanner/rules integrated; Guild trace pending |
| Member 3 | Actor dispatch/recheck, receipt contract | Original two commits integrated |
| Member 4 | Dashboard, coordinator, persistent controlled registrar, Docker, Akash, demo assets | Implemented here; see validation status |

## Integrated snapshots

- `ingest.py`: `feature/clickhouse-ingest` at `9f0ec40ed47acaf3e6185436c4a2a74772df1fbe`.
- `brain/` and `semgrep-rules/`: `timothy` at `3e55a3ecaeef1ab1a2bbd96c93852ce92bf80bd7`.
- Team modules are copied unchanged; Member 4 integration is in `shipper/team_pipeline.py`.
- [Controlled run guide](CONTROLLED_RUN.md): combined supervised command, current
  database adapter, actual Semgrep execution and sponsor evidence limits.
- The combined adapter handles only the owned target. Member 1's public-feed
  CLI remains separate and is not automatically started by this demo.

Provide commands as JSON argv arrays, for example `["python", "-m", "your_actual_module"]` in
`INGEST_COMMAND_JSON` and `SCAN_COMMAND_JSON`. These are **long-running** supervised processes.
A one-shot command must be wrapped by its owner in a polling loop. No shell expansion occurs.
Add pinned dependencies to `requirements-team.txt` and commit the modules before rebuilding the image.

The controlled registrar becomes available at `http://localhost:8099/site` after worker startup.
Ingestion must retry startup connections and tag its rows with the configured `RUN_ID`.
Member 2 must actually fetch and scan this owned page with Semgrep. The bundled form contains a disabled password
field with a reserved `.invalid` action, but stores nothing. Its presence alone is not proof of real-world phishing;
label the rule as a controlled demonstration rule and report its actual output.

## Contract (exactly these keys)

```json
{
  "event_id": "run-001-event-001",
  "target_url": "http://localhost:8099/site",
  "timestamp": "2026-10-09T19:00:00Z",
  "semgrep_detected": false,
  "confidence_score": 0.0,
  "evidence": "",
  "action_status": "PENDING",
  "proof_url": ""
}
```

Database metadata: `ingested_at` (actual insertion time), nullable `scan_completed_at`, `scanner`
(`semgrep` only after the real tool completes), and `run_id`. Use `integration/reference-schema.sql` or
expose a compatible view and set `EVENTS_TABLE`. Keep exactly one current row per event in that view.
Preserve `ingested_at` when scanning finishes. A false detection without scan completion is **pending**.
The coordinator ignores uncompleted, unlabeled, other-run, and noncontrolled events.

For local file integration, set `DATA_SOURCE=files` and atomically replace
`DATA_DIR/runs/RUN_ID/events.json` with an array of objects shaped
`{"event": <exact contract>, "metadata": <the four fields above>}`. `shipper.storage.write_json` is available.
This verifies orchestration but does not count as ClickHouse usage.

## Coordinator and receipts

One worker serializes dispatch and rechecks using a process lock and one ledger. The `actions` table is
created before polling; local JSONL receipts are retried to ClickHouse after outages. Retry identity uses
event, action, status, creation time, and evidence hash. This is a single-replica demo, not a distributed
exactly-once transaction system. Failed dispatches have at most three attempts, fifteen seconds apart.
No wildcard retry of external side effects is enabled.

`actions.jsonl`, `state.json`, `attempts.json`, `synced.json`, and `registrar.json` live under the run directory.
Never erase them to repeat a run. Choose a new deliberate `RUN_ID` for a new recording. Same-run restarts
retain the suspension and ticket. The private endpoint is idempotent for the same event/evidence pair.

The UI reads receipts directly; Member 3 currently does not mutate `incoming_threats.action_status` or
`proof_url`. Only public HTTP(S) proof links are clickable; local proofs are represented by a saved dashboard
receipt view. That view is not an external provider's confirmation.

For the final demo provide: a real ingestion timestamp, actual Semgrep output, Guild AI evaluation URL/artifact,
and a ClickHouse row tied to the same `event_id`. Never mark supplied fixture evidence as a real scan.
