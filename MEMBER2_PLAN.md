# Member 2 — Payload Inspection & Decision Engine

Sponsor tools: **Semgrep**, **Guild AI** · Role: the **Brain**
Branch: `timothy`

This document is the working spec for Member 2. It separates:

- **[DONE]** — built and verified
- **[YOU]** — things only you can do (accounts, decisions, sign-off)
- **[AGENT]** — remaining engineering that can be implemented once the blockers clear
- **[BLOCKED]** — cannot proceed without a decision or something from another member

The slide-style summary is in [MEMBER2_PRESENTATION.md](MEMBER2_PRESENTATION.md); setup and usage are in [brain/README.md](brain/README.md).

---

## 1. Status snapshot

| # | Brief requirement | State |
|---|---|---|
| 1 | Fetcher that pulls the raw HTML/JavaScript from a flagged URL | **[DONE]** `brain/fetcher.py`: text-only GET, 10 s timeout, 3 redirects, 2 MB cap, inline and external scripts extracted, private addresses refused. |
| 2 | Semgrep rules for malicious payloads | **[DONE]** 8 rules in `semgrep-rules/` (credential exfiltration, fake login forms, obfuscated loaders and redirects, shell droppers). |
| 3 | Triage logic producing a structured verdict | **[DONE]** `brain/decide.py`: `semgrep_detected`, `confidence_score`, `evidence`, `action_status` in the team's shared contract. |
| 4 | Guild AI | **[DONE, partly]** Verifier agent built, tested on Guild and saved as a draft. Not yet wired into the automated path (§6). |
| 5 | Comparison against a baseline | **[DONE]** `brain/evaluate.py`: rules against a regex baseline on 15 labelled samples. |
| + | HTTP service | **[DONE]** `brain/service.py`: `POST /scan`, `POST /scan/batch` (1 to 25 events), `X-API-Key` auth. |
| + | Autonomous worker | **[DONE, unverified live]** `brain/worker.py` reads Member 1's table and appends verdicts to `events` (§5). |

---

## 2. Decisions taken

| Decision | Choice | Why |
|---|---|---|
| Render pages in a browser? | No. Plain HTTP GET, text only. | Never executes hostile code; fast. Cost: pages that build their form at runtime are seen only as source. |
| Model in the verdict? | No. Semgrep plus arithmetic. | Deterministic, always returns, and the evidence is a quotable line. The model is a separate second opinion. |
| Threshold for `VERIFIED` | 0.6 | One strong rule is enough to call it a detection. Obfuscation alone (0.4) is not. |
| Follow links to subpages? | No. Scan only the URLs given. | Fewer requests to hostile servers; the reported URL usually carries the evidence. Batch scanning covers callers that supply several URLs. |
| Guild's role | Agent runtime for a verification agent | The older "experiment tracking" idea described a different, discontinued Guild product. |
| Where verdicts are stored | Append-only `events` table, newest row per `event_id` wins | Avoids ClickHouse mutations on the hot path. |
| Verdict table variable | `VERDICTS_TABLE` | Matches the Actor. `EVENTS_TABLE` means the raw feed table there. |

---

## 3. Bugs and gaps found along the way — all FIXED unless noted

### 3.1 Semgrep rejected the first rule file — FIXED
A pattern containing a colon (`fetch("$URL", {..., body: $BODY, ...})`) is read by YAML as a mapping. Patterns are now single-quoted.

### 3.2 Float weights broke rule loading — FIXED
Semgrep rejects float values in rule metadata. Weights are quoted strings, parsed in `scan.py`.

### 3.3 Semgrep and FastAPI cannot share an environment — FIXED
Installing FastAPI upgraded a dependency Semgrep pins. Semgrep is installed separately and found through `SEMGREP_BIN`; it is deliberately absent from `requirements.txt`.

### 3.4 Benign login pages were at risk of being flagged — FIXED
A same-site filter drops findings whose matched URL is on the page's own domain. All benign samples score below the threshold.

### 3.5 Semgrep is slow on Windows — WORKED AROUND
22 s per scan on Windows against 3.5 s on Linux (same version, same rules). Batch scanning runs Semgrep once per batch. Run the service on Linux.

### 3.6 Guild's server build could not see new files — FIXED
Guild uploads only files tracked in the agent directory's own git repo. New source files must be `git add`ed inside `agents/verifier/`.

### 3.7 One variable named two tables — FIXED
`EVENTS_TABLE` meant the verdict table in the Brain and the raw feed table in the Actor. The Brain now reads `VERDICTS_TABLE`.

### 3.8 Every feed row gets the feed bonus — OPEN
`get_pending_events()` sets `listed_on_feed` for any row from URLhaus, OpenPhish or ThreatFox, so every scan gets +0.15. The bonus was meant for a second, independent source. See §8.

---

## 4. The interface other members depend on

### 4.1 Verdict fields (shared contract)

| Field | Set by Member 2 | Notes |
|---|---|---|
| `event_id`, `target_url`, `timestamp`, `proof_url` | No | Passed through unchanged; the worker refuses to write if they differ. |
| `semgrep_detected` | Yes | True when at least one rule matched. |
| `confidence_score` | Yes | 0 to 0.99. |
| `evidence` | Yes | Rule name, file, line range, matched line. |
| `action_status` | Yes | `VERIFIED`, `REJECTED` or `FETCH_FAILED`. |

### 4.2 Entry points

| Caller | Use |
|---|---|
| Same process | `brain.pipeline.process_events(events, listed_on_feed)` returns `[(event, findings)]` in order. |
| HTTP | `POST /scan/batch` with `{"events": [...]}`, `X-API-Key` when `BRAIN_API_KEY` is set. |
| Database | Read the `events` table (`VERDICTS_TABLE`) with `FINAL`. |

Member 3's `actor/intake.py` already uses the first two and acts on the third.

### 4.3 What Member 2 reads

`brain.clickhouse.get_pending_events()` reads `incoming_threats` directly for `event_id`, `target_url`, `timestamp` and `feed_source`, because Member 1's `get_pending_targets()` returns domains without URLs or event IDs.

---

## 5. Acceptance criteria

| # | Criterion | Result |
|---|---|---|
| B1 | Demo phishing page is `VERIFIED` with evidence | **Pass.** 0.95, three rules. |
| B2 | Benign lookalike is `REJECTED` | **Pass.** 0.0, no findings. |
| B3 | Dead URL returns `FETCH_FAILED`, not an exception | **Pass.** |
| B4 | Private and loopback addresses are refused by default | **Pass.** |
| B5 | Batch results keep request order and do not mix findings | **Pass.** |
| B6 | No benign sample reaches the threshold | **Pass.** 0 of 8. |
| B7 | Service rejects requests without the API key when one is set | **Pass.** |
| B8 | Verifier agent builds and runs on Guild | **Pass.** Two test runs; draft validated. |
| B9 | Worker round trip against ClickHouse | **Not verified in the final state.** Passed on a local instance at the first integration commit; skipped since. |
| B10 | Scan of a real feed URL | **Not run.** All runs used our own pages and samples. |

Test suite: 53 passed, 6 skipped (the ClickHouse cases).

---

## 6. Guild AI — state and what is left

| Piece | State |
|---|---|
| Agent `dotimothy~threat-verifier` | **[DONE]** Review-only: takes a scan result plus captured scripts, returns a JSON verdict. Draft saved and validated; not published. |
| Workspace `dotimothy~cyberhack` | **[DONE]** Used for tests. |
| OpenAPI spec for `/scan` and `/scan/batch` | **[DONE]** `brain/openapi.yaml`, written for Guild's integration parser. Not registered. |
| Register the scan service as a Guild integration | **[BLOCKED]** Needs a stable public URL: Guild fixes an integration's base URL at creation. |
| Four-tool workflow (feed check, scan, read capture, write event) | **[AGENT]** Written in `agents/verifier/agent.ts`; only `scan` has a backing service. |
| Trigger so the pipeline can call the agent | **[AGENT]** Likely needs a published version. |
| Publish the agent | **[YOU]** Decide after checking whether publishing makes it visible outside the account. |

---

## 7. Implementation order — status

1. **[DONE]** Semgrep spike: rule syntax, JSON output, behaviour on minified and obfuscated code.
2. **[DONE]** Fetcher, scan, verdict, CLI.
3. **[DONE]** Demo pages, labelled samples, evaluation against a regex baseline.
4. **[DONE]** HTTP service with API key and typed responses.
5. **[DONE]** Guild Verifier agent, tested and saved.
6. **[DONE]** Two obfuscation rules for the samples the first six missed.
7. **[DONE]** Batch scanning.
8. **[DONE]** Worker and verdict table against Member 1's schema.
9. **[YOU]** Run the worker against the shared ClickHouse (`python -m brain.worker --once`, tests with `RUN_CLICKHOUSE_TESTS=1`).
10. **[BLOCKED]** Guild integration, pending a public `/scan` URL.

---

## 8. Risks — current state

| Risk | State |
|---|---|
| Rules fitted to the samples | **Open.** The decoded-request rule matches literal `"fe" + "tch"` and `"at" + "ob"`. Three of six variations were missed. Detection numbers describe the samples, not real kits. |
| Confidence scale does not line up with the Actor | **Open, needs a team decision.** Single-rule verdicts reach 0.6 to 0.75; the Actor acts from 0.80. They are detected but not actioned. |
| Feed bonus applied to every row | **Open.** Either restrict it to URLhaus, as the Actor does for corroboration, or drop it for single-feed rows. |
| Worker unverified against the shared database | **Open.** See B9. |
| One worker per database | **Accepted.** Two workers would scan the same rows; the code documents this. |
| Fetch failures are never retried | **Accepted.** They are marked scanned and left. |
| Fetching live malicious content | **Mitigated.** Text only, never rendered; run in WSL or the container, not on a laptop's host OS. |
| Member 1's files changed on this branch | **Open.** `ingest.py` and `threatfeed.py` carry fixes Member 1's branch does not have; Member 1 should be told. |
| Sample set small and synthetic | **Accepted.** Stated wherever the numbers appear. |
