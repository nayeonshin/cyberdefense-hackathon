# Interface contract — Member 1 → Member 2

Owner: **Member 1** (Threat Ingestion, ClickHouse) · Consumer: **Member 2**
Status: **implemented** — `threatfeed.py`, verified by `tests/smoke_test.py` (decisions D1–D5 resolved, see `MEMBER1_PLAN.md` §3)

This is the only surface Member 2 should depend on. Do not read `incoming_threats`
directly if you can avoid it; the table layout may change, this contract will not.

---

## Import

```python
from threatfeed import get_pending_targets, update_takedown_status
```

Same checkout, same virtualenv. `pip install -r requirements.txt` first.
Connection details come from `clickhouse.env` / `.env` (template:
`clickhouse.env.example`), loaded with the same helper `ingest.py` uses; nothing
is hardcoded. `THREATS_TABLE` (default `incoming_threats`) selects the table —
only tests should set it.

### Run / demo commands

```bash
.venv/bin/python ingest.py                 # pull the latest 50 URLhaus records
.venv/bin/python threatfeed.py             # print the top 5 pending targets
.venv/bin/python -c "from threatfeed import get_pending_targets; [print(r) for r in get_pending_targets(5)]"
.venv/bin/python tests/smoke_test.py       # full contract test on an isolated table
```

---

## `get_pending_targets(limit: int = 5) -> list[dict]`

Returns the highest-velocity unverified targets, **one row per domain**, not per URL.
"Pending" means `takedown_status = 'PENDING'` — i.e. nobody has scanned or actioned it yet.

Ordering: number of reported URLs descending, then most recently seen descending.
A domain with many freshly reported URLs is an active campaign and the best
takedown candidate; a domain with one URL from three weeks ago is not.

```python
[
    {
        "domain":     "evil.example",          # str, lowercased, port stripped
        "url_count":  14,                      # int, distinct PENDING URLs for this domain
        "first_seen": datetime(2026,10,9,18,2,3, tzinfo=timezone.utc),
        "last_seen":  datetime(2026,10,9,18,20,3, tzinfo=timezone.utc),
        # --- additive extension (see below) ---
        "target_urls":  ["http://evil.example/b.exe", "http://evil.example/a.exe"],
        "threat_types": ["malware_download"],
        "ip_address":   "",                    # '' when unknown
    },
    ...
]
```

`url_count`, `first_seen` and `last_seen` are computed over the domain's
`PENDING` rows only (`uniqExact(target_url)`, `min/max(timestamp)`).

### Additive extension (implemented, backwards compatible)

The brief says this function hands *unverified threats* to Member 2, and a
domain alone is not something you can scan. So every row also carries:

| Key | Type | Meaning |
|---|---|---|
| `target_urls` | `list[str]` | Up to **10** distinct pending URLs for the domain, newest first |
| `threat_types` | `list[str]` | Distinct URLhaus `threat` values for those rows, sorted |
| `ip_address` | `str` | Any non-empty `ip_address` among them, else `''` |

The four original keys are unchanged; code that ignores the new keys keeps working.
This answers open question 3 below.

Guarantees:

- At most `limit` rows; may be fewer if fewer domains are pending. Never raises on empty.
- Every returned domain currently has at least one `PENDING` row.
- `limit` must be `>= 1`; passing `0` or a negative raises `ValueError` (a silent
  empty list would be indistinguishable from "no threats", which is worse).
- `limit` must be an `int` — `"5"`, `2.0` and `True` also raise `ValueError`.
- Timestamps are UTC-aware.
- Two consecutive calls with no intervening ingest return the same domains —
  the function does not mutate state.

---

## `update_takedown_status(status, *, domain=None, event_id=None) -> int`

Marks rows as actioned so they stop appearing in `get_pending_targets()`.
Exactly one of `domain` or `event_id` must be given; both or neither raises `ValueError`.

```python
n = update_takedown_status("SCANNED", domain="evil.example")     # -> rows updated
n = update_takedown_status("TAKEN_DOWN", event_id="3607684")     # -> 1
```

Status vocabulary — agree before changing, other services key off these strings:

| Status | Meaning | Set by |
|---|---|---|
| `PENDING` | Reported, nobody has acted | Member 1 (default on ingest) |
| `SCANNING` | Member 2 has picked it up | Member 2 |
| `SCANNED` | Analysis finished, no action needed | Member 2 |
| `TAKEN_DOWN` | Takedown request sent / site neutralised | Member 2 |
| `FALSE_POSITIVE` | Report was wrong | Member 2 |

`status` outside the table below raises `ValueError`; so does an empty-string
selector. All three values are bound as ClickHouse query parameters, never
formatted into SQL.

Return value is the number of rows matched (counted before the update; `0` means
nothing matched and no mutation is issued). **Important caveat:** ClickHouse
`ALTER … UPDATE` is an asynchronous mutation. This function issues it with
`mutations_sync=1` so it has committed by the time the call returns — do not
remove that setting, or the next `get_pending_targets()` will still show the
domain for a few seconds and it will look like a bug.

Rows are never deleted. History is the point — "how fast did we take this down"
is answerable only if the original event survives.

---

## `get_feed_stats(recent: int = 10) -> dict`

Read-only pipeline statistics (additive; for dashboards / the demo). Also printed by
`python threatfeed.py --stats`.

```python
{
  "by_feed":        [{"feed_source": "threatfox", "rows": 119, "pending": 119}, ...],
  "by_threat_type": [{"threat_type": "phishing", "rows": 100}, ...],
  "by_status":      [{"takedown_status": "PENDING", "rows": 289}, ...],
  "recent_runs":    [{"run_ts": datetime(UTC), "feed_source": "urlhaus", "fetched": 1000,
                      "inserted": 20, "duplicates": 0, "error": "", "duration_ms": 1456}, ...],
}
```

`recent_runs` comes from the `ingest_runs` table (newest first, at most `recent`) and is `[]`
if that table does not exist yet. Raises `ValueError` if `recent` is not an int >= 1.

---

## Schema Member 2 may rely on

```sql
incoming_threats
    event_id        String     -- URLhaus id, stable, the dedup key
    target_url      String
    domain          String
    ip_address      String     -- '' if unknown; not every row has one
    `timestamp`     DateTime   -- when URLhaus saw it, UTC
    threat_type     String     -- 'malware_download', 'phishing', ...
    takedown_status String     -- see vocabulary above
```

`ip_address` is explicitly **not guaranteed**: URLhaus usually reports a hostname,
and we do not resolve DNS on the ingest path (slow, and unreliable for sinkholed
malware). Treat `''` as "unknown", not as an error. If Member 2 needs the IP,
resolve it there.

---

## What Member 2 should NOT do

- Do not `INSERT` into `incoming_threats` — Member 1's poller owns that table and
  will overwrite your assumptions about `event_id`.
- Do not run `ALTER TABLE … UPDATE` directly; use `update_takedown_status()`.
- Do not assume the table is non-empty. The feed can legitimately return zero new
  rows; `get_pending_targets()` returns `[]` and that is a valid state.

---

## Open questions for Member 2

1. ~~HTTP endpoint instead of a Python import?~~ **Resolved (D4):** Python import only.
2. Does anything besides the five status strings need to be recorded (analyst name,
   evidence URL, timestamps)? If yes, that is a **new table**, not new columns —
   tell Member 1 before relying on it. *Still open.*
3. ~~Raw URLs for a domain?~~ **Resolved:** `target_urls` (up to 10, newest first).
