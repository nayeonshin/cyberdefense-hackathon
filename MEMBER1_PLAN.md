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

| # | Brief requirement | State |
|---|---|---|
| 1 | ClickHouse instance (local Docker or Cloud) | **[DONE]** container `threat-orchestrator-db`, v26.9.14.10, HTTP on `localhost:8123` |
| 2 | Python ingestion script polling live threat feeds | **[DONE, untested against live API]** `ingest.py` |
| 3 | Schema: `timestamp, target_url, domain, ip_address, threat_type, takedown_status` | **[PARTIAL]** table exists but is missing `domain`, `ip_address`; `action_status` must be renamed to `takedown_status` |
| 4 | Expose `get_pending_targets()` to Member 2 | **[NOT STARTED]** |

Verified working today: schema creation is idempotent, bulk insert works, `DateTime` round-trips with the correct UTC epoch (no local-timezone shift).

---

## 2. [BLOCKED] Hard blocker: URLhaus now requires an Auth-Key

The brief assumes URLhaus is an open API. It is not anymore, since **2025-06-30**.

Measured from this machine right now:

```
GET https://urlhaus-api.abuse.ch/v1/urls/recent/                    -> 401 {"error": "Unauthorized"}
GET ... with header Auth-Key: 00000000000000000000000000000000      -> 403 {"query_status": "unknown_auth_key"}
```

Reference: <https://abuse.ch/blog/community-first/>

**Your action:**

1. Register at <https://auth.abuse.ch/> and copy your Auth-Key.
2. Add it to `clickhouse.env` (this file is gitignored, so the key stays out of history):

   ```
   URLHAUS_AUTH_KEY=<paste-key-here>
   ```
3. Confirm with: `.venv/bin/python ingest.py --dry-run`

Without this, no ingestion can be validated end-to-end. Everything below is written to fail loudly rather than silently insert zero rows, so a misconfigured key will never look like "success".

Also worth knowing: the free tier is rate-limited. Do not run the poller in a tight loop; a 5–15 minute interval is realistic for a demo.

---

## 3. [YOU] Decisions I need from you

These change the schema and the interface, so I have stopped before implementing.

| # | Decision | Options | My recommendation |
|---|---|---|---|
| D1 | How many records per poll? Brief says 20, the earlier exact spec said 50 | `20` / `50` | Keep it configurable (`--limit`), default **50**, since "high-velocity" is the theme. Flip to 20 if the brief must be matched literally. |
| D2 | Filter to phishing only? `urls/recent/` returns all threat types mixed (`malware_download`, `phishing`, …) | all / `phishing` only | Add `--threat-type` filter, default **all**, so the demo shows volume but you can narrow on demand. The brief says "phishing URLs", so if that matters for scoring, default it to `phishing`. |
| D3 | How to fill `ip_address`? URLhaus returns only `host`, which is sometimes an IP literal and sometimes a hostname. It never gives a resolved IP. | (a) fill only when `host` is an IP literal, else `''` (b) add opt-in DNS resolution `--resolve-dns` (c) drop the column | **(a) + (b) behind a flag.** DNS resolution is slow, can be blocked, and lies for sinkholed malware domains — it must not be on the critical path. |
| D4 | How does Member 2 call `get_pending_targets()`? | (a) importable Python function (b) HTTP endpoint (FastAPI) | **(a) now**, (b) only if Member 2 is not in Python. The brief explicitly allows "API/function". |
| D5 | How does Member 2 write status back (`SCANNED`, `TAKEN_DOWN`)? | (a) `ALTER TABLE … UPDATE` (b) `ReplacingMergeTree` + version column (c) separate status table | **(a).** Smallest change, no schema modelling, fine at this volume. Note: ClickHouse mutations are asynchronous — the query must pass `mutations_sync=1` or the status will appear to "not stick" for the seconds before the mutation commits. |

---

## 4. [AGENT] Bugs and gaps found while planning

### 4.1 High severity — the timestamp parser may reject 100% of live rows

The documented `/v1/urls/recent/` sample shows the suffix:

```json
"date_added": "2019-08-10 09:02:05 UTC"
```

`ingest.py:46` uses `URLHAUS_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"`, which cannot parse a trailing `" UTC"`. If the live endpoint uses that format, every row is skipped by `map_records()` and the run reports "0 rows inserted" while looking successful.

I could not verify against the live endpoint because of the 401. Fix is cheap and safe either way: make the parser take the first 19 characters / try both formats. There is no downside to being tolerant here.

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

A2–A6 are all blocked on §2 until the Auth-Key exists.

---

## 8. [AGENT] Implementation order once D1–D5 are answered

1. Fix the `date_added` parser (4.1) and add a unit check over both documented formats.
2. Drop and recreate `incoming_threats` with the §5 column set.
3. Add `domain` / `ip_address` derivation (4.4, D3).
4. Add dedup by `event_id` (4.3).
5. Add `threatfeed.py` with `get_pending_targets()` + `update_takedown_status()` (§6).
6. Extend `/tmp/verify_ingest.py` into a committed smoke test covering A4–A7 against synthetic rows, so it runs without the Auth-Key.
7. Optional: second feed (crt.sh CT log JSON, no auth required) behind `feed_source`.
8. Commit to `feature/clickhouse-ingest`.

---

## 9. Open risks

| Risk | Impact | Mitigation |
|---|---|---|
| No Auth-Key | No live ingestion; whole deliverable unprovable | §2 — your action |
| `date_added` format differs from what the parser expects | Silent 0-row ingest | Fix 4.1; A2 catches it explicitly |
| URLhaus `urls/recent/` is a sliding window, not an event stream | Duplicates, inflated velocity counts | Dedup on `event_id` (4.3) |
| `urls/recent/` may return fewer than `--limit` records | Demo shows fewer rows than the brief implies | Already logged: `URLhaus returned N records` |
| Rate limiting on the free tier | Poller breaks mid-demo | Poll on an interval, never in a loop; handle 429 explicitly (already done) |
| ClickHouse mutation is async | Member 2 reports a status that is not visible yet | `mutations_sync=1` (D5) |
| Verified only against synthetic data | Live payload shape unconfirmed | A2/A3 close this immediately once the key exists |
