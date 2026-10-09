# Cyberdefense Hackathon MVP Plan: Active Threat Takedown Orchestrator

Event: [Cyberdefense Hackathon #SFTechWeek](https://luma.com/cyberhack?tk=1HbKiY), AWS Builder Loft, San Francisco.

The earlier agent-firewall plan is kept in [docs/agent-firewall-plan.md](docs/agent-firewall-plan.md).

## Constraints

- Hack window is about 5.5 hours: kickoff 11:00 AM, submission 4:30 PM.
- Submit a 3-minute demo video at https://tokensand.com/cyberhack/submit before 4:30 PM.
- Must use at least 3 sponsor tools. We use four: ClickHouse, Semgrep, Guild AI, Akash.
- Tracks: attack intelligence (primary), autonomous remediation (secondary).

## The idea

An agent that watches threat feeds for malicious URLs, inspects what each one serves, and when the evidence holds up, files an abuse report and publishes a public warning, with no manual step.

**One-line pitch:** from threat feed to filed abuse report in under a minute, with code-level evidence attached.

## Pipeline and owners

| # | Stage | Owner | Sponsor tool |
|---|---|---|---|
| 1 | **Monitor:** poll threat feeds, store candidates, serve pending targets | Member 1 | ClickHouse |
| 2 | **Brain:** fetch the payload, scan it, verify it, produce a verdict | Member 2 | Semgrep, Guild AI |
| 3 | **Actor:** look up the registrar or host, send the abuse report, publish the warning, log the receipt | Member 3 | ClickHouse (action log) |
| 4 | **Ship:** container, Akash deployment, dashboard, demo video, submission | Member 4 | Akash |

## Team-level refinements

These change the original task split and need the whole team's agreement.

### 1. Append a new version of the event instead of updating it

ClickHouse is built for inserts; updating `action_status` on an existing row is an asynchronous mutation and will make the dashboard lag or look wrong. Keep the shared contract as the row shape, and have each member insert a **new full row** for the same `event_id` with their fields filled in. The table keeps the newest version:

```sql
CREATE TABLE events (
    event_id         String,
    target_url       String,
    timestamp        DateTime64(3, 'UTC'),
    semgrep_detected Nullable(Bool),
    confidence_score Nullable(Float32),
    evidence         String DEFAULT '',
    action_status    LowCardinality(String) DEFAULT 'PENDING',
    proof_url        String DEFAULT '',
    updated_at       DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(updated_at)
ORDER BY event_id;
```

Read with `SELECT ... FROM events FINAL` to get one current row per event. `updated_at` is storage-only and not part of the JSON. This sketch has not been run yet.

### 2. Pick a feed whose payloads Semgrep can read

URLhaus is a malware-distribution feed, not a phishing feed: most entries point at binaries or shell-script droppers, and many are already offline. JavaScript rules will find almost nothing there. Two fixes, do both:

- Add a phishing feed (OpenPhish's free list) for live HTML and JS.
- Plant two pages we host ourselves, one phishing and one benign lookalike, so the demo never depends on a third-party site being up.

URLhaus stays useful as an independent confirmation source: "also listed on URLhaus" is a strong second signal.

### 3. Gate the real-world actions

Member 3's actions are real and outward-facing: emails to real abuse desks and public posts naming URLs. A false positive there accuses a legitimate site in public. Proposed rules:

- Send only when two independent signals agree: a Semgrep finding **and** a listing on a trusted feed.
- Cap real abuse emails at a handful for the whole event; everything else goes to an inbox we own.
- Defang URLs in anything published (`hxxps://evil[.]example`), which is the convention for threat-intel feeds.
- The demo's planted phishing page takes the full path, including a real public warning, because we own it.

### 4. Handle live malicious content safely

Member 2's fetcher downloads from hostile servers. Fetch as text only, never render or execute, and run it inside WSL or the container rather than directly on a laptop. Details are in the Member 2 section.

### 5. Guild AI is an agent platform, not an experiment tracker

The original task ("track test runs against sample datasets") describes Guild's older open-source ML experiment toolkit. The Guild AI sponsoring this event is a control plane for running agents: TypeScript SDK, CLI, cron and webhook triggers, custom REST endpoints registered as tools, and a trace of every action. The plan below uses it that way. Ask at their booth whether an evaluation feature exists; if it does, the labelled test set below can feed it.

## Contracts

The team's shared data contract. Every member reads and writes this exact structure:

```json
{
  "event_id": "evt-10928",
  "target_url": "https://malicious-login-fake.com",
  "timestamp": "2026-10-09T11:00:00Z",
  "semgrep_detected": true,
  "confidence_score": 0.96,
  "evidence": "Semgrep rule `credential-stealer` matched lines 42-48",
  "action_status": "PUBLISHED_TAKEDOWN",
  "proof_url": "https://github.com/myteam/threat-feed/issues/12"
}
```

Two things the contract leaves open, to settle in the first 15 minutes:

**Who fills which fields**

| Member | Sets | Leaves as |
|---|---|---|
| 1 | `event_id`, `target_url`, `timestamp`, `action_status: "PENDING"` | `semgrep_detected: null`, `confidence_score: null`, `evidence: ""`, `proof_url: ""` |
| 2 | `semgrep_detected`, `confidence_score`, `evidence`, `action_status` | `proof_url: ""` |
| 3 | `action_status`, `proof_url` | Everything else unchanged |

**Allowed `action_status` values** (the example only shows the last one)

| Value | Set by | Meaning |
|---|---|---|
| `PENDING` | 1 | Ingested, not yet scanned |
| `VERIFIED` | 2 | Malicious with confidence at or above the threshold; Member 3 acts on these |
| `REJECTED` | 2 | Scanned, not malicious or not confident enough; nothing is sent |
| `FETCH_FAILED` | 2 | Site unreachable or not scannable content |
| `PUBLISHED_TAKEDOWN` | 3 | Report sent and warning published; `proof_url` set |
| `ACTION_FAILED` | 3 | Send or publish failed |

**Handoffs** are then two queries on the current rows: Member 2 takes `action_status = 'PENDING'`; Member 3 takes `action_status = 'VERIFIED'`.

`evidence` is a single string. Member 2 formats it as: rule name, file and line range, then the matched line, for example ``Semgrep rule `cross-origin-credential-post` matched kit.js lines 6-9: await fetch("https://collector…``. If Member 3 needs the full findings for the abuse notice, the `/scan` response carries them as an extra `findings` array outside the shared contract.

## Member 2 plan: payload inspection and decision engine

Build it in four layers. Each layer works without the next one, so there is always something to demo.

### Layer 1: fetcher

`fetch_target(url) -> capture_dir`

- Plain HTTP GET; no browser, no JavaScript execution.
- 10-second timeout, at most 3 redirects, 2 MB cap, text content types only (HTML, JS, JSON, shell scripts). Anything else is recorded as "binary, not scanned".
- Save `page.html`, pull inline `<script>` blocks out into `inline_N.js`, and fetch same-page external scripts into the same directory.
- One fresh directory per target; nothing in it is ever opened or run.
- Record failures (DNS, timeout, 404) as a verdict with `fetch_ok: false` rather than an exception, since many feed URLs are already dead.

### Layer 2: Semgrep scan

`scan_capture(capture_dir) -> findings`, running `semgrep scan --config semgrep-rules/ --json`.

| Rule | Detects | Category | Weight | Status |
|---|---|---|---|---|
| `cross-origin-credential-post` | `fetch`, `XMLHttpRequest`, `sendBeacon` or `$.post` sending form values to a hard-coded external URL | credential harvester | 0.6 | Built |
| `telegram-bot-exfil` | Requests to `api.telegram.org/bot…/sendMessage` | credential harvester | 0.7 | Built |
| `fake-login-form` | A password input in a form whose `action` is an absolute URL on another site | credential harvester | 0.6 | Built |
| `obfuscated-loader` | `eval` or `document.write` on `atob`, `unescape` or `String.fromCharCode` output | obfuscated loader | 0.4 | Built |
| `obfuscated-redirect` | `window.location` assigned from a decoded string | obfuscated redirect | 0.3 | Built |
| `shell-dropper` | `wget` or `curl`, then `chmod`, then execution (for URLhaus entries) | malware dropper | 0.7 | Built |
| `decoded-credential-request` | Password values sent to decoded URLs through direct fetch or concatenated window fetch/atob aliases | credential harvester | 0.6 | Built and tested |
| `escaped-remote-script` | Percent-encoded remote script tags inserted with `document.write(unescape(...))` | obfuscated loader | 0.4 | Built and tested |

**Status: layers 1 to 3 and the `/scan` service are built and tested** (see [brain/README.md](brain/README.md) for validation). Before the new rules, 7 tests passed and the rules detected 5 of 7 malicious samples with 0 of 6 benign flagged. The two new rules detect both misses: `evasive` scores 0.6 and `obfuscated-eval` scores 0.64. With two new benign counterexamples, the rules detect 7 of 7 malicious and flag 0 of 8 benign; the regex baseline detects 5 of 7 and flags 7 of 8 benign. A real uvicorn run returned VERIFIED (0.95) for the phishing demo and REJECTED (0.0) for the benign demo.

**Remaining for Member 2:** bind and test the [Guild Verifier workflow](agents/verifier/README.md) once the public scanner URL and integration operations are available. Local `npm run build` passes and Guild CLI login is valid; MCP is unavailable. The default agent reviews supplied sources without tools; the workflow factory can call the scanner, feeds, capture reader and event writer after binding. This run has not uploaded or published that workflow. The Python suite passes (13 tests, including a concurrently added API-key test and five new rule cases). The follow-on task is written up in [docs/codex-task.md](docs/codex-task.md).

Notes from the spike on Semgrep 1.180.0:

- A pattern containing a colon, such as `fetch("$URL", {..., body: $BODY, ...})`, must be wrapped in single quotes or the YAML is rejected.
- Rules match minified code. The new decoded-credential-request rule catches the sample with a base64-encoded URL and `window["fe"+"tch"]`; it also requires a password value, so benign decoded search requests stay below threshold.
- On Windows, install Semgrep into a venv with a short path (the install fails on long paths) and set `PYTHONUTF8=1`. Running in WSL or the container avoids both.
- Semgrep needs its own environment: its pinned dependencies conflict with FastAPI's.
- Rule metadata can't hold float values, so weights are quoted strings.
- `extra.lines` in the JSON output needs a Semgrep login, so the scanner reads the matched lines from the file itself.

### Layer 3: verdict

`decide(findings, target) -> verdict`, plain Python with no model, so it always works.

- `confidence_score` = 1 − ∏(1 − weight) over the distinct rules that matched, so two medium findings outrank one.
- Add 0.15 if the target is also listed on an independent feed; cap at 0.99.
- `semgrep_detected` = at least one rule matched.
- `action_status` = `VERIFIED` if the score is ≥ 0.6, `FETCH_FAILED` if the fetch failed, otherwise `REJECTED`.
- `evidence` = rule name, file, line range and source line of the highest-weight finding.

**Test set:** seven malicious and eight benign captures in `samples/`, with a script that prints detection rate and false-positive rate for the Semgrep rules against a regex baseline. This is the "compare against baseline" task, and the numbers go on a slide. These synthetic fixtures are a small sanity check, not a production benchmark.

### Layer 4: Guild agent

Wrap layers 1 to 3 in a small FastAPI service (`POST /scan` takes the shared event JSON and returns it with Member 2's fields filled in), then put a Guild agent on top.

| Piece | Detail |
|---|---|
| Agent | One LLM-template agent, "Verifier" |
| Trigger | Webhook, called by the pipeline for each pending target; cron as an alternative |
| Tools | `scan` (our `/scan` service), `check_feeds` (is this URL on URLhaus or OpenPhish), `write_event` (insert the updated event row into ClickHouse) |
| Job | Call `scan`, cross-check against the feeds, and when Semgrep finds nothing on a suspicious page, read the script itself and say why. Write the final verdict. |
| What it adds | The "verify against truthful sources" step, coverage for obfuscated code that the rules miss, and a trace of every decision for the demo |

Guild's runtime is hosted, so `/scan` needs a public URL: a tunnel during development, then Member 4's Akash deployment.

**Fallback:** if the Guild agent isn't calling `/scan` by 2:30 PM, the pipeline calls `/scan` directly and writes the layer 3 verdict. Guild then runs as a second-opinion step on one or two targets for the demo.

### Member 2 schedule

| Time | Goal |
|---|---|
| 11:00–11:15 | Agree contracts; get one sample target from Member 1, or hard-code one |
| 11:15–12:00 | Fetcher; planted phishing and benign pages |
| 12:00–1:00 | Semgrep rules, scan, verdict JSON; `/scan` service running |
| 1:00–1:30 | Hand `/scan` to Members 1 and 3 so the pipeline runs end to end |
| 2:00–3:00 | Guild agent: register tools, webhook trigger, trace visible |
| 3:00–3:30 | Test set numbers; extra rules |
| 3:30–4:00 | Support the demo recording |

### Files

- `brain/fetcher.py`, `brain/scan.py`, `brain/decide.py`, `brain/service.py`
- `semgrep-rules/*.yaml`
- `samples/malicious/`, `samples/benign/`, `brain/evaluate.py`
- `agents/verifier/` (Guild, TypeScript)
- `demo-sites/phish/`, `demo-sites/benign/`

## Notes for the other members

- **Member 1:** use the `events` table above; `get_pending_targets()` is `SELECT ... FROM events FINAL WHERE action_status = 'PENDING'`. Add the two planted demo pages and a phishing feed alongside URLhaus.
- **Member 3:** take events with `action_status = 'VERIFIED'`, then insert a new row with `PUBLISHED_TAKEDOWN` and the `proof_url`. Apply the gating rules above before any real send.
- **Member 4:** the container needs Python, Semgrep and the rules directory. The dashboard reads `events FINAL` and can show `evidence` directly. Start recording by 3:30 PM; the video is the submission.

## Demo video outline (3 minutes)

1. **0:00–0:25:** Feed rows arriving in ClickHouse on the dashboard.
2. **0:25–0:45:** Our planted phishing page enters the feed.
3. **0:45–1:30:** The Brain: Semgrep finding with the exact line, confidence score, Guild trace of the verification.
4. **1:30–2:15:** The Actor: abuse report sent, public warning published, receipt link on the dashboard.
5. **2:15–2:40:** The benign lookalike goes through and nothing is sent.
6. **2:40–3:00:** It all runs on Akash; test-set numbers; pitch line.

## Open questions

- **Guild AI:** which models and credits hackathon teams get, and whether an evaluation feature exists.
- **Feeds:** whether OpenPhish's free list is reachable from the venue; cache a copy beforehand.
- **Real sends:** the team's decision on how many real abuse emails to send, and to whom.
- **Pre-built code:** whether the rules allow it.
