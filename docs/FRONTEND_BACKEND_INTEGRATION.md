# Frontend and backend integration

This branch merges frontend `d03f00e` (PR #2) and backend `c45c38b` (PR #3). The
merge was conflict-free; PR #3 already included cherry-picked copies of the
motion UI. Both original branches remain available for separate review.

## Connect the UI to Members 1–3

Install `requirements-dev.txt` for development or `requirements.txt` plus
`requirements-team.txt` for the container. Database connection settings belong
in ignored `.env` / `clickhouse.env` files or process environment variables.
Process variables take priority. Do not put credentials in Git or public SDL.

For an existing backend, set:

```dotenv
DATA_SOURCE=backend
RUN_MODE=preview
THREATS_TABLE=incoming_threats
VERDICTS_TABLE=events
ACTIONS_TABLE=actions
```

Use `akash_threats`, `akash_events`, and `akash_actions` if that is the backend's
configured table namespace. Then run `python -m streamlit run dashboard.py`.
`RUN_MODE=preview` here means the dashboard does not execute actions; displayed
data is real backend data and is not labeled as simulated. No extra Actor is
started. Members 1–3 retain ownership of their ingestion, scanner and Actor
entrypoints. The dashboard only needs SELECT access.

`DATA_SOURCE=clickhouse` remains the original controlled-run adapter using
`EVENTS_TABLE=shipper_events`. It is a different schema from the backend tables.
`DATA_SOURCE=files` and explicitly labeled fixtures remain supported.

## What is projected

- Ingestion rows are deduplicated by event ID. `first_seen` is ingestion time;
  upstream feed timestamps are not throughput measurements.
- The newest scanner/Actor version is read from the verdict table with FINAL.
  Event IDs and target URLs must both match before evidence is joined.
- Pending nullable fields get strict eight-field presentation defaults, with
  completion tracked separately. Failed fetches do not become negative scans.
- Actor outcome versions can replace the original scanner row. A completed
  scan remains complete, but its original timestamp is shown as unavailable;
  the Actor's later update time is never used as the scan time.
- Receipt status is authoritative for action progress. Test messages do not
  count as submissions. Private/unsafe proof URLs remain non-clickable.
- Missing verdict/receipt tables are valid startup states. No tables are
  created by opening or refreshing the dashboard. Missing ingestion tables,
  denied queries and connection failures remain visible errors.
- The queue shows up to 200 events; metrics aggregate the full configured
  backend tables. The receipt panel reads the latest 500 matching receipts.
- Backend worker heartbeats are not exposed by this schema. The UI says so,
  keeps motion stopped, and treats previous unavailability receipts as
  historical. It neither probes targets nor invents fresh worker health.

## Validation and rollout

The initial merged tree passed 140 tests with 9 opt-in tests skipped locally.
New regression tests cover schema projection, pending/negative/failed cases,
unknown scan times, receipt matching, unsafe names/links and read-only UI reruns.
The integration CI job also starts a disposable ClickHouse instance and runs
the native Member 1/2 roundtrip and new frontend adapter tests against it. The
existing controlled pipeline, persistence, database recovery and worker-failure
container checks remain enabled.

[Final CI run 38003354360](https://github.com/nayeonshin/cyberdefense-hackathon/actions/runs/38003354360)
passed **152 tests / 10 skips** in the default suite and then **all 8 native
ClickHouse roundtrip tests** with the opt-in database enabled. The combined
controlled pipeline completed in **14.225 seconds**, retained one submitted
receipt through persistent-volume restart and database outage/recovery, and
exposed a forced worker exit. The offline Actor benchmark passed all **124
scenarios**, score 100, with zero reported safety violations.

Tested image:
`ghcr.io/nayeonshin/cyberdefense-hackathon:50273c8a725a9bcbc36fc04b10377e8cb495551a`.
Digest: `sha256:a7b31b86f648f2931061e5293562304e07d77a19c6f5112e87f1bcaa3ccb8486`.
The final documentation commit only records these results; the code is the
image commit above. Existing animation assets are unchanged from PR #2.

No existing Akash lease is updated by this integration experiment. The tested
integration image can be reviewed before a separate deployment decision.
Guild AI is not used. The backend's optional Guild scaffold is retained as
inactive source only; it is not part of the Python runtime or claimed validation.

## Credential follow-up

PR #3 included a shared ClickHouse password. This branch replaces that document
with environment setup instructions; an ignored local backup preserves the
team's existing setup. The credential still exists in upstream commit history
and must be rotated by the database owner. No history was rewritten.
