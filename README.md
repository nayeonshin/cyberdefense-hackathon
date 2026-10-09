# Active Threat Takedown Orchestrator — Member 1 (the Monitor)

Live URLhaus threat feed → ClickHouse → `threatfeed.get_pending_targets()` for Member 2.

The scanner integration is documented in [brain/README.md](brain/README.md).
After ingestion, run `python -m brain.worker --once` to batch-scan pending URL
events and persist verdicts. `python -m brain.telemetry --output graph-data.json`
exports domain activity, threat-type counts and current scanner verdict counts.
The integration tests use isolated tables/databases and owned demo targets.

| File | Purpose |
|---|---|
| `ingest.py` | Polls URLhaus `/v1/urls/recent/`, maps records, dedups on `event_id`, inserts into `incoming_threats` |
| `threatfeed.py` | Member 2's interface: `get_pending_targets()`, `update_takedown_status()` (contract: `INTERFACE.md`) |
| `tests/smoke_test.py` | End-to-end checks on an isolated table (`incoming_threats_test`), never touches live data |
| `check_setup.py` | Read-only preflight: deps, ClickHouse, Auth-Key, live payload, schema |
| `MEMBER1_PLAN.md` | Spec, decisions D1–D5, acceptance results |

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp clickhouse.env.example clickhouse.env   # then fill in CLICKHOUSE_PASSWORD and URLHAUS_AUTH_KEY
docker compose up -d                       # ClickHouse on localhost:8123
.venv/bin/python check_setup.py            # must end with "No blockers"
```

`clickhouse.env` is gitignored. Get a free URLhaus Auth-Key at <https://auth.abuse.ch/>
(mandatory since 2025-06-30). Never commit or screen-share it.

## Ingest

```bash
.venv/bin/python ingest.py --dry-run               # fetch + map only, DB untouched
.venv/bin/python ingest.py                         # one-shot: 50 most recent records
.venv/bin/python ingest.py --feeds all --limit 100 # urlhaus + openphish (phishing) + threatfox (C2); --limit is per feed
.venv/bin/python ingest.py --reset-schema          # first run after a schema change: DROP + recreate
.venv/bin/python ingest.py --threat-type phishing  # only one threat type (may legitimately be 0)
.venv/bin/python ingest.py --limit 100 --resolve-dns
```

Polling (off by default; minimum 300 s to respect URLhaus rate limits):

```bash
.venv/bin/python ingest.py --interval 600          # Ctrl-C to stop
```

Autonomous mode — runs all feeds forever with no manual intervention:

```bash
.venv/bin/python ingest.py --daemon                          # Ctrl-C / SIGTERM -> "daemon stopped"
.venv/bin/python ingest.py --daemon --max-cycles 2 --interval 60 --limit 20   # bounded demo
.venv/bin/python threatfeed.py --stats                       # rows per feed/type/status + recent runs
```

Each feed has its own schedule (urlhaus 300 s, openphish 600 s, threatfox 600 s); `--interval`
overrides them (minimum 60 s). A failing feed backs off (interval doubles, capped at 1 h) and resets
after a success. Every cycle logs a heartbeat (`cycle`, due feeds, total rows), and every feed
attempt is recorded in the `ingest_runs` table (not written in `--dry-run`; a failed stats write only
logs a warning). `--max-cycles N` stops the daemon after N cycles.

Exit codes: `0` ok, `1` runtime error (HTTP/DB), `2` bad arguments,
`3` the feed returned records but none could be mapped (parser regression — never reported as success).

## Use the feed (Member 2)

```bash
.venv/bin/python threatfeed.py                     # prints the top 5 pending targets
```

```python
from threatfeed import get_pending_targets, update_takedown_status

for t in get_pending_targets(5):
    print(t["domain"], t["url_count"], t["target_urls"])
update_takedown_status("TAKEN_DOWN", domain="evil.example")   # visible immediately
```

## Tests

```bash
.venv/bin/python tests/smoke_test.py               # ends with "ALL CHECKS PASSED"
.venv/bin/python ingest.py --self-test             # parser-only, no network/DB
```
