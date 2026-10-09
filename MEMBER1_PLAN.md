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

Phase 1 (ingest) is complete and verified against the **live** URLhaus API on 2026-10-09.

| # | Brief requirement | State |
|---|---|---|
| 1 | ClickHouse instance (local Docker or Cloud) | **[DONE]** container `threat-orchestrator-db`, server version `26.9.14.10`, HTTP on `localhost:8123` (A1). Connection is env-driven (`CLICKHOUSE_HOST/PORT/USER/PASSWORD`), so swapping to ClickHouse Cloud is a config change, not a code change. |
| 2 | Python ingestion script polling live threat feeds | **[DONE]** `ingest.py` polls the live authenticated `/v1/urls/recent/` endpoint: A2 maps `50/50`, A3 inserts 50 rows into an empty table. |
| 3 | Schema: `timestamp, target_url, domain, ip_address, threat_type, takedown_status` | **[DONE]** all six brief columns present (A4); `timestamp` is `DateTime`, `takedown_status` is `String`. Rebuilt via DROP + recreate. |
| 4 | Expose `get_pending_targets()` to Member 2 | **[PHASE 2]** `threatfeed.py` not implemented yet. |

Verified today: the container is up and authenticated (`SELECT version()` -> `26.9.14.10`), the Auth-Key in `clickhouse.env` is accepted by the live API (`query_status: ok`, 1000 records), the timestamp parser handles the live `date_added` format (8/8 self-checks), 50 rows insert into a fresh table, and a second back-to-back run inserts **0** rows (dedup by `event_id`).

---

## 2. [RESOLVED] URLhaus requires an Auth-Key

The brief assumes URLhaus is an open API. It is not anymore, since **2025-06-30**;
without a key the endpoint returns 401, and with an invalid key 403. Reference:
<https://abuse.ch/blog/community-first/>

**Status: resolved.** `URLHAUS_AUTH_KEY` is now present in `clickhouse.env`
(gitignored, 48-char key). Measured live on 2026-10-09: HTTP 200,
`query_status: "ok"`, 1000 records returned. `ingest.py` reads it from the
environment and never logs it.

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

## 4. [AGENT] Bugs and gaps found while planning

### 4.1 High severity — the timestamp parser rejected 100% of live rows — **FIXED, and the theory was CONFIRMED**

The suspicion was that `/v1/urls/recent/` emits a trailing zone marker. **Measured live on 2026-10-09: it does.**

```json
"date_added": "2026-10-09 18:55:15 UTC"
```

All **1000 / 1000** records in the polled window carried the ` UTC` suffix. The old
`URLHAUS_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"` could not parse it, so `parse_timestamp()`
returned `None` for every record, `map_records()` skipped them all, and `main()`
still exited **0** while logging `Mapped 0/N` — a total failure that looked like success.

**Fixed:** `parse_timestamp()` now tolerates a trailing ` UTC` (case-insensitive), a bare
form, ISO-8601 with a `T` separator, a trailing `Z`, and a numeric offset; the result is
always UTC-aware (`datetime.fromisoformat`/`strptime` + `replace(tzinfo=timezone.utc)`).
Verified by `ingest.py --self-test` (8/8, covering both documented formats plus ISO-8601
and the four reject cases).

**Second guard added:** `main()` now refuses to report success on the silent-failure
signature. If the feed returned data, the filter is `all`, and *nothing* maps, it logs an
explicit error naming a `date_added` format mismatch and exits **3** instead of 0.

### 4.2 Column set does not match the brief

Current (`ingest.py:53`): `event_id, target_url, timestamp, threat_type, action_status`
Required: `timestamp, target_url, domain, ip_address, threat_type, takedown_status`

`incoming_threats` is **currently empty**, so this is a clean `DROP` + recreate, not a migration.

### 4.3 No deduplication

`urls/recent/` is a sliding window. Polling twice re-inserts overlapping URLs, so "top 5 unscanned domains" inflates with duplicates and row counts stop meaning anything. `event_id` (URLhaus `id`) is stable and is the natural dedup key.

### 4.4 `domain` needs a defined derivation rule

Grouping by domain is the core of the "top 5 unscanned domains" query, so the rule must be pinned down or the grouping silently splits. Proposal: prefer the API's `host` field; fall back to `urllib.parse.urlsplit(target_url).hostname`; lowercase it; **keep** a literal IP as its own value; strip the port.

---

## 5. [AGENT] Proposed schema (pending D1–D5)

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

## 6. [AGENT] The interface Member 2 depends on

Full contract in `INTERFACE.md`. Shape:

```python
get_pending_targets(limit: int = 5) -> list[dict]
# -> [{"domain": str, "url_count": int, "first_seen": datetime, "last_seen": datetime}, ...]

update_takedown_status(domain: str | None = None,
                       event_id: str | None = None,
                       status: str = "SCANNED") -> int
```

Backing query for "top 5 unscanned domains":

```sql
SELECT domain,
       count()            AS url_count,
       min(`timestamp`)   AS first_seen,
       max(`timestamp`)   AS last_seen
FROM incoming_threats
WHERE takedown_status = 'PENDING'
GROUP BY domain
ORDER BY url_count DESC, last_seen DESC
LIMIT {limit}
```

`ORDER BY url_count DESC` is what makes it a *high-velocity* view: the domain with the most freshly reported URLs is the most active campaign, and the best takedown candidate.

---

## 7. [YOU] Acceptance criteria — what you must verify yourself

I can build these, but you own the sign-off. Run each and confirm.

| # | Check | Command | Expected |
|---|---|---|---|
| A1 | DB reachable | `curl -s -u default:hackathon123 "http://localhost:8123/?query=SELECT+version()"` | `26.9.14.10` |
| A2 | Key works, mapping works, DB untouched | `.venv/bin/python ingest.py --dry-run` | logs `Mapped N/N records`, prints sample rows, no writes |
| A3 | Real insert | `.venv/bin/python ingest.py` | logs `Insert completed`, then a verification row count > 0 |
| A4 | Schema matches brief exactly | `curl -s --data-binary "DESCRIBE TABLE incoming_threats" "http://localhost:8123/" -u default:hackathon123` | the 6 required columns present, `timestamp` is `DateTime` |
| A5 | Interface works for Member 2 | `.venv/bin/python -c "from threatfeed import get_pending_targets; [print(r) for r in get_pending_targets(5)]"` | 5 rows, all `PENDING`-backed, ordered by `url_count` desc |
| A6 | Dedup holds | run `ingest.py` twice back-to-back, then check `count()` | second run adds ~0 new rows when the feed window has not moved |
| A7 | Status write-back is visible | call `update_takedown_status(status='TAKEN_DOWN')` for one domain, re-run A5 | that domain is gone from the pending list |

**Phase 1 result (measured 2026-10-09 against the live API, raw output in the completion report):**

| # | Result |
|---|---|
| A1 | **PASS** — `SELECT version()` -> `26.9.14.10` |
| A2 | **PASS** — `Mapped 50/50 records for insertion`, 5 sample rows printed, DB untouched |
| A3 | **PASS** — `Insert completed`; `count()` -> 50 on a fresh table |
| A4 | **PASS** — all six brief columns present; `timestamp` is `DateTime`; `takedown_status` is `String` |
| A5 | **Deferred to Phase 2** — needs `threatfeed.py` |
| A6 | **PASS** — second back-to-back run: `Done: 0 row(s) inserted, 50 duplicate(s) skipped` |
| A7 | **Deferred to Phase 2** — needs `update_takedown_status()` |

A2–A6 are no longer blocked: §2 is resolved.

**Caveat on A6:** the measured churn of `urls/recent/` is tiny — over a 12-second
window the top-50 `id`s were **identical** (overlap 50/50, `id` of record 0 unchanged
at `3947111`). So the dedup check is meaningful, but a second run "adding 0 rows" also
reflects a feed that had not moved at all, not only dedup blocking it. Dedup was
exercised directly: run #1 skipped 49 duplicates and inserted the 1 genuinely new `id`.

---

## 8. [AGENT] Implementation order — Phase 1 status

| # | Step | State |
|---|---|---|
| 1 | Fix the `date_added` parser (4.1) and add a unit check over both formats | **[DONE]** `parse_timestamp()`; `.venv/bin/python ingest.py --self-test` -> 8/8 |
| 2 | Drop and recreate `incoming_threats` with the §5 column set | **[DONE]** `ingest.py --recreate` |
| 3 | Add `domain` / `ip_address` derivation (4.4, D3) | **[DONE]** `derive_domain()`, `derive_ip_address()`, `--resolve-dns` |
| 4 | Add dedup by `event_id` (4.3) | **[DONE]** `drop_duplicates()` |
| 5 | Add `threatfeed.py` with `get_pending_targets()` + `update_takedown_status()` (§6) | **[PHASE 2]** |
| 6 | Extend `/tmp/verify_ingest.py` into a committed `tests/smoke_test.py` covering A4–A7 against synthetic rows, so it runs without the Auth-Key | **[PHASE 2]** (`ingest.py --self-test` is the Phase 1 placeholder) |
| 7 | Optional: second feed (crt.sh CT log JSON, no auth required) behind `feed_source` | **[BACKLOG]** |
| 8 | Commit to `feature/clickhouse-ingest` | **[ORCHESTRATOR]** — not committed by Member 1 |

---

## 9. Risks — current state

| Risk | Impact | Mitigation / status |
|---|---|---|
| ~~No Auth-Key~~ | ~~No live ingestion~~ | **[RESOLVED]** key present in `clickhouse.env`; rotate after the hackathon (§2) |
| ~~`date_added` format differs from what the parser expects~~ | ~~Silent 0-row ingest~~ | **[RESOLVED, theory confirmed]** live format is `... UTC`; parser now tolerant, `--self-test` guards it, and `main()` exits 3 rather than 0 on the all-skipped signature |
| URLhaus `urls/recent/` is a sliding window, not an event stream | Duplicates, inflated velocity counts | Dedup on `event_id` (4.3) — A6 |
| `urls/recent/` may return fewer than `--limit` records | Demo shows fewer rows than the brief implies | Logged: `URLhaus returned N records`; `Mapped N/M` makes the ratio explicit |
| Rate limiting on the free tier | Poller breaks mid-demo | Poll on an interval, never in a loop; HTTP 429 raises explicitly |
| ClickHouse mutation is async | Member 2 reports a status that is not visible yet | `mutations_sync=1` (D5) — Phase 2 |
| The `urls/recent/` window is **all `malware_download`** at present (0 `phishing` in 1000 rows) | A `--threat-type phishing` demo would legitimately show 0 rows | Documented in §3 D2; `--threat-type` defaults to `all` so the demo has volume. Re-check the mix before a phishing-only demo. |
| Table mismatch if the old 5-column table is still live | Inserts would fail against the brief's column set | `assert_schema()` refuses mismatched tables; `--recreate` rebuilds (the intended one-off path, since the table was empty) |
