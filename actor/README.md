# Actor: autonomous action and dispatch (Member 3)

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

- Major platforms are allowlisted: a bad URL there is reported per URL, never as a domain.
- IPs on shared infrastructure are never reported to an IP reputation list.
- One report per domain and channel, five per recipient per hour.
- Pages for people show defanged URLs; the evidence bundle is hashed and the hash is quoted
  in every report.
- The Actor never downloads the reported page. urlscan.io fetches it, and rechecks use `HEAD`.
- Fixture verdicts carry `"simulated": true` and are never sent, even with `--live`.
