# Member 1 — Threat Ingestion & High-Velocity Data Layer

Sponsor tool: **ClickHouse** · Role: the **Monitor**
Branch: `feature/clickhouse-ingest` · Baseline commit: `46ef3fc`

This document is the working spec for Member 1. It separates:

- **[DONE]** — already built and verified
- **[YOU]** — things only you can do (secrets, decisions, sign-off)
- **[AGENT]** — remaining engineering I can implement once you answer the open decisions
- **[BLOCKED]** — cannot proceed without a decision or an external credential

---

## 1. Status snapshot

**All four brief deliverables are done** and verified against the **live** URLhaus API on 2026-10-09 (Phases 1–3).

| # | Brief requirement | State |
|---|---|---|
| 1 | ClickHouse instance (local Docker or Cloud) | **[DONE]** container `threat-orchestrator-db`, server version `26.9.14.10`, timezone `UTC`, HTTP on `localhost:8123` (A1). Connection is env-driven, so ClickHouse Cloud is a config change (§2.1). |
| 2 | Python ingestion script polling live threat feeds | **[DONE]** `ingest.py` polls the live authenticated `/v1/urls/recent/` endpoint (one-shot, or `--interval ≥300`): A2 maps `50/50`, A3 inserts 50 rows. |
| 3 | Schema: `timestamp, target_url, domain, ip_address, threat_type, takedown_status` | **[DONE]** all six brief columns present (A4); `timestamp` is `DateTime`. Rebuilt via `ingest.py --reset-schema`. |
| 4 | Expose `get_pending_targets()` to Member 2 | **[DONE]** `threatfeed.py` (`get_pending_targets`, `update_takedown_status`), contract in `INTERFACE.md`, A5/A7 pass live and in `tests/smoke_test.py` (82/82). |

Optional extras from the brief (CT logs, simulated phishing list) are **not** implemented — see §8 step 7.

---

## 2. [RESOLVED] URLhaus requires an Auth-Key

The brief assumes URLhaus is an open API. It is not anymore, since **2025-06-30**;
without a key the endpoint returns 401, and with an invalid key 403. Reference:
<https://abuse.ch/blog/community-first/>

**Status: resolved.** `URLHAUS_AUTH_KEY` is present in `clickhouse.env`
(gitignored). Measured live on 2026-10-09: HTTP 200, `query_status: "ok"`,
1000 records returned. `ingest.py` and `check_setup.py` read it from the
environment and never log it.

**Action item:** the key is a personal credential that will be in the same
gitignored file when the hackathon ends — **rotate or revoke it at
<https://auth.abuse.ch/> after the event.** Do not let it end up in a screen
share, a screenshot, or a copied shell history.

Also worth knowing: the free tier is rate-limited. Do not run the poller in a tight loop; a 5–15 minute interval is realistic for a demo. `ingest.py` raises explicitly on HTTP 429 rather than retrying blindly.

---

## 2.1 Where the database lives — local Docker vs. shared ClickHouse Cloud

Phase 1 was verified against the **local Docker container** (`localhost:8123`,
`default` / the password in `clickhouse.env`). That is fine for one machine, but a
teammate cannot reach another teammate's `localhost`.

The connection is **entirely env-driven** (`CLICKHOUSE_HOST/PORT/USER/PASSWORD/SECURE`),
so this is a config decision, not a code change:

| Setup | `CLICKHOUSE_HOST` | Notes |
|---|---|---|
| Local Docker (current) | `localhost` | Works for one machine only. Each teammate runs their own container and their own `incoming_threats` — fine for parallel dev, wrong for a shared demo. |
| **ClickHouse Cloud (recommended for the team)** | `<instance>.<region>.clickhouse.cloud` | Everyone points at one service. Set `CLICKHOUSE_SECURE=1` and the HTTPS port (`8443`). Each teammate uses their own cloud user/credentials, so the key in `clickhouse.env` stays per-machine. |

`ingest.py` now reads `CLICKHOUSE_SECURE` and defaults the port to `8443` when it is on,
so switching the whole team to the cloud service is a four-line `clickhouse.env` change.
See `clickhouse.env.example` for a ready-to-fill cloud block.

**Not done / not verified:** the cloud path has never been exercised from this machine —
no cloud service exists yet. Ask each teammate to create their own ClickHouse Cloud
account (the $300 trial credit is per account) and share **one** service, then put the
service host in `clickhouse.env`. Confirm with A1 before relying on it.
---

## 3. [FROZEN] Decisions — resolved by the orchestrator

These were open when this plan was drafted. They are now closed; the implementation in `ingest.py` reflects them and they should not be re-litigated.

| # | Decision | Resolved choice | Rationale |
|---|---|---|---|
| D1 | Records per poll | `--limit`, default **50** | "High-velocity" is the theme, and 50 vs 20 is a flag away. |
| D2 | Threat-type filter | `--threat-type` filter, default **all** | `--threat-type phishing` is a one-flag switch that works. The threat-type breakdown of every poll is logged. Note: the live window was **100 % `malware_download` at the time of writing** — a `phishing` run legitimately maps 0 rows, which is why the filter is not on by default. |
| D3 | `ip_address` | Fill only when URLhaus's `host` is an IP literal, else `''`; opt-in `--resolve-dns` for best-effort resolution | DNS is slow, blockable, and lies for sinkholed malware domains. It is **off by default**, **never raises**, and is not on the critical ingest path — a failure yields `''`. |
| D4 | Member 2 calling convention | Importable Python module `threatfeed.py` | No HTTP endpoint; the brief explicitly allows "API/function". |
| D5 | Status write-back | `ALTER TABLE … UPDATE` issued with `mutations_sync=1` | Smallest change, no schema modelling. ClickHouse mutations are otherwise asynchronous, which makes a status look like it "did not stick". Applies to Phase 2's `update_takedown_status()`. |

---

## 4. Bugs and gaps found while planning — all FIXED

### 4.1 High severity — the timestamp parser rejected 100% of live rows — **FIXED; the ` UTC` theory was CONFIRMED**

Measured live payload (2026-10-09, `GET /v1/urls/recent/`, HTTP 200):

- top-level keys: `query_status`, `urls` (1000 records)
- record keys: `blacklists, date_added, host, id, larted, reporter, tags, threat, url, url_status, urlhaus_reference`
- record 0: `date_added = '2026-10-09 18:59:08 UTC'`, `host = 'www.tmcksa.com'`, `threat = 'malware_download'`, `url_status = 'online'`
- **1000 / 1000** `date_added` values end in ` UTC`; 828 / 1000 `host`s are IP literals; no `host` carried a port.

The old `"%Y-%m-%d %H:%M:%S"` could not parse that, so every record was skipped and
`main()` still exited **0** while logging `Mapped 0/N` — a total failure that looked like success.

**Fixed:** `parse_timestamp()` accepts the bare form, a trailing ` UTC`, ISO-8601 with `T`,
a trailing `Z`, and numeric offsets; always returns a UTC-aware datetime; returns `None`
for garbage. Covered by `ingest.py --self-test` (32/32) and `tests/smoke_test.py`.

**Fail-loud guard:** if records matching the `--threat-type` filter came back and *none* map,
`ingest.py` logs an explicit error and exits **3**. A filter that legitimately matches nothing
(e.g. `phishing` today) logs a warning and exits 0. Verified by the smoke test (bogus feed → exit 3).

### 4.2 Column set did not match the brief — **FIXED**

Old: `event_id, target_url, timestamp, threat_type, action_status`.
Now the §5 column set; `action_status` is renamed to `takedown_status` everywhere.
`ingest.py --reset-schema` (alias `--recreate`) drops and recreates the table; without it a
mismatched table is refused with a clear `RuntimeError` instead of `CREATE IF NOT EXISTS`
silently keeping the old shape.

### 4.3 No deduplication — **FIXED**

`drop_duplicates()` runs one parameterized `SELECT … WHERE event_id IN {ids:Array(String)}`
and also collapses repeats inside a batch. Logged as `Dedup: N new, M duplicates skipped`.

### 4.4 `domain` derivation rule — **FIXED**

Prefer the API's `host`; fall back to `urlsplit(target_url).hostname`; lowercase; strip the
port and trailing dot; keep IP literals as-is. If neither yields a host the row is skipped
with a warning — `domain` is never stored empty.

---

## 5. Schema (implemented)

```sql
CREATE TABLE IF NOT EXISTS incoming_threats
(
    event_id        String,               -- URLhaus `id`, the dedup key
    target_url      String,               -- URLhaus `url`
    domain          String,               -- derived, see 4.4
    ip_address      String,               -- '' when unknown, see D3
    `timestamp`     DateTime,             -- URLhaus `date_added`, stored as UTC
    threat_type     String,               -- URLhaus `threat`
    takedown_status String DEFAULT 'PENDING',
    feed_source     LowCardinality(String) DEFAULT 'urlhaus',  -- optional, see 5.1
    first_seen      DateTime DEFAULT now()                     -- optional, see 5.1
)
ENGINE = MergeTree
ORDER BY `timestamp`
```

5.1 `feed_source` and `first_seen` are **additions beyond the brief**, not substitutions. `feed_source` becomes worth having the moment a second feed (CT log / simulated phishing list) is added; `first_seen` lets you measure ingestion lag and is the honest way to answer "is this feed still alive?". Drop both if the judging is strict about the exact column list.

`ORDER BY timestamp` is kept deliberately: the earlier exact spec mandated `MergeTree` ordered by `timestamp`, and it is the right ordering for a time-windowed poller. Deduplication is therefore handled explicitly rather than by `ReplacingMergeTree`.

---

## 6. The interface Member 2 depends on (implemented in `threatfeed.py`)

Full contract in `INTERFACE.md`, which is authoritative. Shape:

```python
get_pending_targets(limit: int = 5) -> list[dict]
# -> [{"domain", "url_count", "first_seen", "last_seen",          # contract keys
#      "target_urls", "threat_types", "ip_address"}, ...]        # additive keys

update_takedown_status(status: str, *, domain: str | None = None,
                       event_id: str | None = None) -> int
```

Backing query (simplified; all caller values are bound parameters):

```sql
SELECT domain,
       uniqExact(target_url) AS url_count,
       min(`timestamp`)      AS first_seen,
       max(`timestamp`)      AS last_seen,
       arraySlice(... groupArray((`timestamp`, target_url)) newest first ..., 1, 10) AS target_urls,
       arraySort(groupUniqArray(threat_type)) AS threat_types,
       anyIf(ip_address, ip_address != '')    AS ip_address
FROM incoming_threats
WHERE takedown_status = {pending:String}
GROUP BY domain
ORDER BY url_count DESC, last_seen DESC
LIMIT {limit:UInt32}
```

Write-back: count matches, then
`ALTER TABLE incoming_threats UPDATE takedown_status = {status:String} WHERE domain = {selector:String}`
with `settings={"mutations_sync": 1}` (D5).

`ORDER BY url_count DESC` ranks by *activity*: the domain with the most freshly reported URLs is the most active campaign, and the best takedown candidate. (This is not "velocity"; ingest velocity is measured separately in §10.)

---

## 7. Acceptance criteria

| # | Check | Command | Expected |
|---|---|---|---|
| A1 | DB reachable | `curl -s -u "default:$CLICKHOUSE_PASSWORD" "http://localhost:8123/?query=SELECT+version()"` | `26.9.14.10` |
| A2 | Key works, mapping works, DB untouched | `.venv/bin/python ingest.py --dry-run` | logs `Mapped N/N records`, prints sample rows, no writes |
| A3 | Real insert | `.venv/bin/python ingest.py` | logs `Insert completed`, then a verification row count > 0 |
| A4 | Schema matches brief exactly | `curl -s --data-binary "DESCRIBE TABLE incoming_threats" "http://localhost:8123/" -u "default:$CLICKHOUSE_PASSWORD"` | the 6 required columns present, `timestamp` is `DateTime` |
| A5 | Interface works for Member 2 | `.venv/bin/python threatfeed.py` | 5 rows, all `PENDING`-backed, ordered by `url_count` desc |
| A6 | Dedup holds | run `ingest.py` twice back-to-back | second run: `Dedup: 0 new, M duplicates skipped` |
| A7 | Status write-back is visible | `.venv/bin/python tests/smoke_test.py` (and live: `update_takedown_status("TAKEN_DOWN", domain=X)`, re-run A5) | X gone from the pending list immediately |

**Result (measured 2026-10-09 against the live API):**

| # | Result |
|---|---|
| A1 | **PASS** — `26.9.14.10` |
| A2 | **PASS** — `URLhaus returned 1000 records`, `malware_download=1000`, `Mapped 50/50 records for insertion`, DB untouched |
| A3 | **PASS** — `--reset-schema` run: `Dedup: 50 new, 0 duplicates skipped`, `Insert completed`, `holds 50 row(s), 50 PENDING` |
| A4 | **PASS** — 9 columns incl. all six brief columns; `timestamp` is `DateTime` |
| A5 | **PASS** — top 5 live: `tronzadorasnng.com` (7 URLs), `github.com` (3), `www.tmcksa.com` (2), `114.226.200.81` (2), `micstndasap.world` (2) |
| A6 | **PASS** — second run: `Dedup: 0 new, 50 duplicates skipped`, `Done: 0 row(s) inserted` |
| A7 | **PASS** — smoke test: `busy.example gone from pending IMMEDIATELY`; live: `update_takedown_status('TAKEN_DOWN', domain='tronzadorasnng.com') -> 7`, gone from the next call (then restored to `PENDING`) |
| — | `tests/smoke_test.py`: **ALL CHECKS PASSED (82 checks)**; `check_setup.py`: **No blockers** |
| — | `--threat-type phishing --dry-run`: **0** matches in 1000 records (feed was 100 % `malware_download`) |

**Caveat on A6:** `urls/recent/` churns slowly (≈1 new `id` per few minutes), so "0 new"
on an immediate re-run partly reflects an unmoved window. Dedup itself is proven
independently by the smoke test (re-insert of 7 known rows → 0 added).

---

## 8. Implementation order — status

| # | Step | State |
|---|---|---|
| 1 | Fix the `date_added` parser (4.1) + fail-loud exit 3 | **[DONE]** |
| 2 | Drop and recreate `incoming_threats` with the §5 column set | **[DONE]** `ingest.py --reset-schema` |
| 3 | `domain` / `ip_address` derivation (4.4, D3) | **[DONE]** `--resolve-dns` uses a 2 s timeout, never raises |
| 4 | Dedup by `event_id` (4.3) | **[DONE]** |
| 5 | `threatfeed.py` with `get_pending_targets()` + `update_takedown_status()` (§6) | **[DONE]** |
| 6 | `tests/smoke_test.py` (replaces `/tmp/verify_ingest.py`), isolated table `incoming_threats_test` | **[DONE]** 82/82 |
| 6a | Optional polling loop `--interval SECONDS` (≥300) | **[DONE]** |
| 7 | Optional: second feed (crt.sh CT log / simulated phishing list) behind `feed_source` | **[BACKLOG]** not started |
| 8 | Commit to `feature/clickhouse-ingest` | **[DONE]** local commits, not pushed |

---

## 9. Risks — current state

| Risk | Impact | Mitigation / status |
|---|---|---|
| ~~No Auth-Key~~ | ~~No live ingestion~~ | **[RESOLVED]** key present in `clickhouse.env`; rotate after the hackathon (§2) |
| ~~`date_added` format differs from what the parser expects~~ | ~~Silent 0-row ingest~~ | **[RESOLVED, theory confirmed]** live format is `... UTC`; parser now tolerant, `--self-test` guards it, and `main()` exits 3 rather than 0 on the all-skipped signature |
| URLhaus `urls/recent/` is a sliding window, not an event stream | Duplicates, inflated velocity counts | **[MITIGATED]** dedup on `event_id` (4.3) — A6 |
| `urls/recent/` may return fewer than `--limit` records | Demo shows fewer rows than the brief implies | Logged: `URLhaus returned N records`; `Mapped N/M` makes the ratio explicit |
| Rate limiting on the free tier | Poller breaks mid-demo | **[MITIGATED]** `--interval` enforces ≥300 s; HTTP 429 raises explicitly; in polling mode a failed poll is logged and retried next interval |
| ClickHouse mutation is async | Member 2 reports a status that is not visible yet | **[RESOLVED]** `mutations_sync=1` (D5), proven by A7 |
| The `urls/recent/` window is **all `malware_download`** (0 `phishing` in 1000 rows, re-measured at verification time) | A phishing-only demo shows 0 rows | `--threat-type` defaults to `all`. Re-check the mix before a phishing-only demo. |
| Old 5-column table still live on a teammate's machine | Inserts fail against the new column set | `assert_schema()` refuses it with a clear error; run `ingest.py --reset-schema` once |
| Auth-Key / password in `clickhouse.env` | Credential leak | Gitignored, never logged; **rotate the Auth-Key after the hackathon** |
| `ip_address` mostly empty for hostname-based URLs | Member 2 lacks an IP | By design (D3); `--resolve-dns` opt-in, or resolve in Member 2 |
| `get_pending_targets` keeps a domain pending if *any* of its rows is PENDING | A partially actioned domain reappears | Intended: aggregates cover PENDING rows only; mark by `domain=` to clear it fully |
| ~~`drop_duplicates` sent every id in one HTTP form field~~ | ~~Any poll over ~5k records crashed (`Field value too long`, ClickHouse's 128 KiB `http_max_field_value_size`)~~ | **[FIXED, found by `--bench`]** lookup chunked at 2000 ids; regression check in `tests/volume_test.py` §4 (25k ids) |
| "High-velocity" read as a claim about the live feeds | Credibility with judges | **[ADDRESSED]** §10: capacity and live feed rate are measured and reported separately |

---

## 10. Velocity & volume — two numbers, never one

"High-velocity" is a claim about **two different things**, and they are measured separately.

| | **A. Capacity** (`ingest.py --bench`) | **B. Live feed rate** (`threatfeed.py --stats`) |
|---|---|---|
| Question | How fast can the ClickHouse layer absorb threat rows? | How fast do the real feeds actually deliver new threats? |
| Data | Synthetic, deterministic (seeded), reserved `.invalid` domains / TEST-NET IPs, `feed_source='bench'` | Real URLhaus / OpenPhish / ThreatFox |
| Path | The **real** `drop_duplicates` + `insert_rows`, one bulk insert per simulated poll, then the real `get_pending_targets()` | The daemon, end to end incl. network |
| Where | Isolated `incoming_threats_bench`, dropped afterwards; nothing written to `ingest_runs` | `ingest_runs` telemetry → `get_feed_stats()["throughput"]` |
| Tested by | `tests/volume_test.py` §2 (floor: ≥ 10k rows/s, query p50 ≤ 2 s; overridable) | `tests/volume_test.py` §3 (rate maths, cold-start excluded) |

**A. Capacity — measured 2026-10-09, local Docker, ClickHouse 26.9.14.10, 16-core laptop:**

| Volume | Batch | End-to-end (dedup + insert) | Insert-only | `get_pending_targets(5)` p50 at that volume | 1-batch redelivery rejected in |
|---|---|---|---|---|---|
| 100,000 rows | 10,000 | **~92–99k rows/s** (1.0 s) | ~145–150k rows/s | 25–29 ms | 35–41 ms |
| 1,000,000 rows | 50,000 | **~206k rows/s** (4.9 s) | ~1.03M rows/s | 94 ms | 244 ms |

All integrity checks pass at both sizes: exact row count, every `event_id` unique, a redelivered batch adds 0 rows, ranking by `url_count` desc. At 1M rows dedup is ~80 % of the time (it is a lookup against a growing table); a `ReplacingMergeTree` would remove it, but `ORDER BY timestamp` was mandated (§5), so it stays explicit.

**B. Live feed rate — what the feeds really deliver (from `ingest_runs`):**

- The pipeline *processes* URLhaus at ~730 records/s of working time (1000 records fetched, mapped and deduped in ~1.4 s per poll).
- The feeds *emit* new threats slowly: URLhaus `urls/recent/` adds ≈1 new id every few minutes (§7 caveat on A6). A cold start can bring in 1000 records at once; after that, most of each poll is duplicates.
- `steady_new_per_hour` reports the real emission rate once a daemon has run for ≥ 10 minutes; it excludes the cold-start backlog on purpose.

**How to say it:** *"The live feeds are our real-time source; they deliver a few new IOCs per minute. The ClickHouse layer underneath is built for high velocity: ~100k threat rows/s through the same dedup + insert path, 1M rows in under 5 s, and Member 2's query still answers in under 100 ms at that volume."* Do not present number A as the feed rate.
