# Real controlled pipeline

The adapter discovers the team's private page, runs Member 2's actual Semgrep CLI
and rules, and lets the independent Actor submit to the mock registrar. It keeps
the exact eight-field contract. External reporting channels remain disabled.
The page has disabled controls, a reserved `.invalid` destination, and a Content
Security Policy that blocks data collection.

Install `requirements-dev.txt` for tests, or both `requirements.txt` and
`requirements-team.txt` for runtime. Dependencies include Semgrep 1.180.0.

PowerShell, from the repository:

```powershell
$env:DATA_SOURCE = 'files'
$env:RUN_MODE = 'controlled'
$env:RUN_ID = 'controlled-demo-001'
$env:DATA_DIR = '.runtime/controlled'
$env:PORT = '8502'
$env:TEAM_PIPELINE_COMMAND_JSON = '["' + ((Resolve-Path '.venv/Scripts/python.exe').Path.Replace('\','/')) + '","-m","shipper.team_pipeline"]'
.\.venv\Scripts\python.exe -m shipper.supervisor
```

Open `http://localhost:8502`. The pipeline starts automatically; no dashboard
button starts or changes an action. A deliberate new demonstration needs a new
RUN_ID. Restarting the same run preserves its scan, ticket and duplicate suppression.
Never delete the ledger to repeat a recording.

From a second shell with the same environment:

```powershell
.\.venv\Scripts\python.exe -m shipper.verify_run --wait 150 --output .runtime/controlled/verification.json
```

`scan-findings.json` saves real rule IDs, source lines and the scanner source commit.
`events.json`, `actions.jsonl` and `target-check.json` preserve the timeline and
fresh confirmation. File mode is actual Semgrep execution, but is **not** ClickHouse usage.

## ClickHouse handoff

Member 1's current ClickHouse is localhost-only on their laptop. A reachable
external instance is still needed for the Akash demonstration.

With that instance configured in the ignored `.env`, set DATA_SOURCE=clickhouse
and EVENTS_TABLE=shipper_events. The adapter uses Member 1's `ensure_schema`,
`drop_duplicates` and `insert_rows` against `incoming_threats`. Owned observations
use `feed_source=controlled_owned_target`, never `urlhaus`. Ingestion time comes
from the real database `first_seen` column.

Member 1's table stays unchanged. The adapter creates `shipper_event_versions`
and the deduplicated `shipper_events` view for the contract and separate metadata.
The Actor bootstraps its actions table. Database failures remain visible with
no fixture fallback. `integration/reference-schema.sql` is an older alternative
contract reference; do not apply it over Member 1's table.

## Sponsor evidence limits

- Semgrep: actual CLI findings are saved by the controlled run and CI acceptance run.
- ClickHouse: only count a run after it successfully uses a reachable database.
- Akash: only count a running lease after browser live updates are verified.
- Guild: Member 2 documents review-only tests on Guild. Obtain their actual trace;
  this adapter does not invoke Guild or claim its use.

The container acceptance job creates a fresh, isolated ClickHouse container on a
private Docker network. It runs the database adapter, actual Semgrep and Actor,
then restarts the application with the same ledger volume and verifies database
receipts plus a fresh suspension check. Its disposable `ci-only` password is not
a deployment credential. Passing CI verifies integration, not a public cloud service.
