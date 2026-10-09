# Actor: autonomous action and dispatch (Member 3)

![Actor bench drawing sheet: verdict stamp, scenario matrix, acceptance table and revision history](bench/scorecard.svg)

The sheet is redrawn by `python -m actor.bench`. It runs 113 labelled scenarios through the
real dispatcher with every outside channel replaced by a recorder.

- **View A** shows every scenario against every action: a filled square was sent as required,
  a blank was held back as required, anything red is a nonconformance.
- **Acceptance** shows how the score is made up. One safety violation makes a run UNSAFE
  whatever the score.
- **Revisions** is the history of runs, and the stamp is the verdict of the latest one.

Scenarios are in [bench/scenarios.yaml](bench/scenarios.yaml); `bench/scorecard.html` adds the
list of nonconformances. The lettering is a subset of Routed Gothic (SIL Open Font License,
see [bench/assets](bench/assets/LETTERING-LICENSE.txt)).

Takes a verified verdict and acts on it, one rung at a time. Every action writes a receipt.

| Rung | Action | Fires when | Leaves the machine |
|---|---|---|---|
| 0 | `feed`: publish to the public feed repo (`feed.json`, `blocklist.txt`, `hosts.txt`, incident page) | confidence >= 0.80 | with `LIVE_FEED=1` |
| 1 | `urlscan`, `netcraft`, `abuseipdb` | confidence >= 0.90 | with the channel's `LIVE_*=1` |
| 2 | `notify_host`: abuse report by mail to the hosting abuse contact (RDAP) | confidence >= 0.95 and `corroborated` | mail sink unless `LIVE_EMAIL=1` |
| 3 | `notify_registrar`: same report to the registrar | still up after 10 minutes | mail sink unless `LIVE_EMAIL=1` |
| 4 | `confirm`: two failed checks in a row mark the target down and resolve the feed entry | always | no |

Thresholds, the allowlist and the rate limit are in [policy.yaml](policy.yaml).

## Run

```bash
python -m actor.dispatch fixtures/verdicts.json          # dry run, prints the plan
python -m actor.dispatch verdict.json --live             # executes the enabled channels
python -m actor.dispatch --poll --live                   # follows the ClickHouse table
python -m actor.recheck --live --loop                    # rungs 3 and 4
python -m unittest discover -s tests                     # 16 tests, no network needed
```

Needs `requests`, `pyyaml` and `clickhouse-connect`. Copy `.env.example` to `.env`.

Nothing is sent without `--live`, and each outside channel also needs its own `LIVE_*=1`.
A file named `STOP` in the repo root halts every action.

## Tested on real threat data

The bench scenarios are hand-written. `actor/history.py` checks the same code on real data:
822,439 threat URLs (URLhaus last 30 days, OpenPhish, Phishing.Database) loaded into
ClickHouse and replayed through the Actor's parser and rules of engagement. Nothing is sent.

```bash
python -m actor.history load urlhaus_recent.csv openphish.txt phishing_active.txt
python -m actor.history replay
python -m actor.history lookup loginmicrosoftonlne.com
```

| | First replay | After the fixes |
|---|---|---|
| Crashes | 0 | 0 |
| Refused as malformed | 620 | 3 |
| Reported per URL only (shared platform) | not counted | 110,705 |

What the real data changed:

- 617 live phishing sites use an underscore in the host name (`uphold_login...`). The parser
  refused them. They are accepted now.
- 13 percent of the URLs sit on shared platforms. Public IPFS gateways and storage APIs were
  among the busiest hosts and were not on the allowlist, so the Actor would have blocked a
  whole gateway. They are on it now.

Both findings became bench scenarios first, then fixes.

The same table feeds the reports. With `HISTORY_LOOKUP=1` every evidence bundle, incident
page and abuse mail states what is already on record for the host, for example
"1023 malicious URLs on record for this host (phishing-database)". The lookup runs on the
table's sort key: 66 ms median from a laptop over 822,439 rows.

## Live checks

The bench proves the decisions with every channel replaced by a recorder. `actor/live.py`
proves the channels themselves:

```bash
python -m actor.live          # read-only: credentials, reachability, latency
python -m actor.live --full   # also pushes a self-test entry to the feed and removes it again
```

It checks ClickHouse (write and lookup), the Semgrep scanner on the demo page, urlscan.io,
Netcraft's development endpoint, the public feed repository, the controlled target and the
mail sink. Results land in `bench/live.json`, in the ClickHouse table `live_checks` and on
sheet 2 of `bench/scorecard.html`.

## The whole pipeline

Three processes follow one ClickHouse database:

```bash
python ingest.py --daemon              # Member 1: feeds into incoming_threats
python -m brain.worker                 # Member 2: scans pending rows, appends verdicts to events
python -m actor.intake --live --loop   # Member 3: acts on VERIFIED verdicts
```

The Actor appends its outcome to the same event in `events`: `PUBLISHED_TAKEDOWN` with a
proof link when something went out, `WITHHELD` when the rules of engagement refused, and
`TAKEN_DOWN` once two failed checks confirm it. `incoming_threats.takedown_status` is set to
`TAKEN_DOWN` at that point as well. A listing on URLhaus, OpenPhish or ThreatFox counts as
the independent second source the Actor needs before it mails a host.

Without a separate scanner worker, `python -m actor.intake --scan --live` calls the scanner
itself, and `--rows fixtures/pipeline_rows.json` runs the same thing without a database.

Local run with the real scanner: `SEMGREP_BIN` pointing at Semgrep, `BRAIN_ALLOW_PRIVATE=1`,
and `SITE_DIR=demo-sites/phish python -m actor.mock_registrar_server` serving Member 2's demo
page as the controlled target.

## For the other stages

**Verdicts in (Members 1 and 2).** `--poll` reads rows with this query; override it with
`VERDICTS_QUERY` in `.env` if the table differs:

```sql
SELECT event_id, target_url, toString(timestamp) AS timestamp, semgrep_detected,
       confidence_score, evidence
FROM incoming_threats
WHERE semgrep_detected
  AND event_id NOT IN (SELECT event_id FROM actions WHERE NOT dry_run)
```

Two optional columns change what the Actor does: `corroborated` (a second source confirms
the threat; without it the host is never mailed) and `threat_type` (`phishing` or `malware`).
From Python: `from actor.dispatch import dispatch; receipts = dispatch(verdict_dict, live=True)`.

**Receipts out (Member 4).** One row per action in the append-only `actions` table, created
on first write. Join on `event_id`.

```sql
SELECT event_id, action, rung, recipient, status, proof_url, latency_ms, detail, created_at
FROM actions WHERE NOT dry_run ORDER BY created_at DESC
```

`status` is one of `PLANNED`, `SENT`, `SINK` (mail kept in the sink), `SKIPPED` (a guardrail
said no, the reason is in `detail`), `FAILED`, `STILL_UP`, `CONFIRMED_DOWN`. For
`CONFIRMED_DOWN`, `latency_ms` is the time from the first action to the takedown.

## Controlled target

Real takedowns take longer than a demo. `python -m actor.mock_registrar_server` serves a
harmless lookalike page on `http://localhost:8099/site` together with a mock registrar. Then:

```bash
python -m actor.dispatch fixtures/controlled.json --live   # ticket filed, site suspended
python -m actor.recheck --live                             # run twice: confirmed down
```

`POST http://localhost:8099/reset` restores the page. Controlled targets only ever reach the
mock registrar and the mail sink.

## Guardrails

- Malformed verdicts are refused with a stated reason: bad `event_id`, a target that is not
  http or https, a confidence outside 0 to 1, a private address as target.
- Major platforms are allowlisted: a bad URL there is reported per URL, never as a domain.
- IPs on shared infrastructure are never reported to an IP reputation list.
- One report per domain and channel, five per recipient per hour.
- Pages for people show defanged URLs; the evidence bundle is hashed and the hash is quoted
  in every report.
- The Actor never downloads the reported page. urlscan.io fetches it, and rechecks use `HEAD`.
- Fixture verdicts carry `"simulated": true` and are never sent, even with `--live`.
