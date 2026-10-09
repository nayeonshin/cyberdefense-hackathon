# Cyberdefense Hackathon MVP Plan: Agent Firewall

Event: [Cyberdefense Hackathon #SFTechWeek](https://luma.com/cyberhack?tk=1HbKiY), AWS Builder Loft, San Francisco.

## Constraints

- Hack window is about 5.5 hours: kickoff 11:00 AM, submission 4:30 PM, finalist demos 5:00 PM.
- Must use at least 3 sponsor tools.
- Demo must fit in under 3 minutes.
- Sponsors: OpenAI, MongoDB, ClickHouse, Semgrep, Akash, ElevenLabs, Pi, Guild AI.
- Track: continuous defense.

## The idea

A firewall for AI browsing agents: a proxy that every web fetch from an agent passes through, which decides whether the page is safe for the agent to read.

**Threat:** a browsing agent treats page content as trusted input. An attacker hides instructions in the page (white-on-white text, `display:none` divs, HTML comments, alt text, or text assembled by JS) and the agent follows them: leaking secrets, calling tools, or lying to the user. This is indirect prompt injection.

**One-line pitch:** agents read parts of the web that humans never see; we inspect those parts before the agent does.

## Flow for one page fetch

1. The agent calls `fetch_page(url)`, which goes to the firewall instead of the web.
2. The firewall renders the page (Playwright) and extracts two views:
   - **human view:** the text a person would see;
   - **agent view:** the full DOM text, including hidden elements, comments and attributes.
3. The diff between the two views is computed. Text only the agent can see is suspicious by default.
4. The page goes through the detection pipeline and gets a verdict: allow, sanitize or block.
5. On sanitize, the agent receives the page with the flagged spans stripped. On block, it gets a refusal with the reason.

## Detection pipeline

One FastAPI endpoint, `POST /verdict`, runs the stages in order and stops early on a cache hit.

| # | Stage | What it does | Sponsor tool |
|---|---|---|---|
| 1 | Fast path | Embed the agent-view text and search known injection payloads and cached verdicts. A close match returns immediately, with no model call. | MongoDB Atlas Vector Search |
| 2 | Hidden-text diff | Compute agent-view minus human-view. No sponsor tool; plain Python. | — |
| 3 | Static scan | Custom rules over the HTML and inline JS: hidden-element styling, JS that injects text after load, forms posting credentials cross-origin. | Semgrep |
| 4 | Decision model | Takes the diff, the Semgrep hits and the page text; returns a structured verdict with evidence spans. | OpenAI |
| 5 | Telemetry | Insert one event per verdict (URL, category, action, per-stage latency) for the live dashboard. | ClickHouse |

### Verdict shape

```json
{
  "action": "allow | sanitize | block",
  "category": "prompt_injection | data_exfiltration | phishing | malicious_script | benign",
  "confidence": 0.0,
  "evidence": [{ "source": "diff | semgrep | model | cache", "span": "...", "reason": "..." }],
  "sanitized_text": "...",
  "latency_ms": { "cache": 0, "semgrep": 0, "model": 0, "total": 0 },
  "cached": false
}
```

## Sponsor tools

| Tool | Role | Priority |
|---|---|---|
| **OpenAI** | Decision model with structured output. Also powers the vulnerable demo agent and the embeddings. | Core |
| **MongoDB Atlas** | Stores every verdict and a corpus of known injection payloads; vector search catches repeat and near-duplicate attacks. | Core |
| **Semgrep** | Deterministic evidence from custom rules, alongside the model's judgment. | Core |
| **ClickHouse** | Verdict events and the live dashboard: blocks per minute, attack types, latency percentiles. | Core |
| **ElevenLabs** | Spoken alert when a page is blocked. Cheap to add and memorable in a demo. | Easy add |
| **Akash** | Host an open guard model (Llama Guard or Prompt Guard) on a rented GPU as a fast first-pass classifier before OpenAI. | Stretch |
| **Guild AI** | Agent control plane with permissions and execution traces. Run the demo agent inside it so each block shows up in the trace. | Decide at event |
| **Pi** | Product-security platform for codebases; no fit in the runtime path. Could scan our own firewall code. | Decide at event |

Four core tools, so one can fail and we still meet the three-tool rule.

## Components to build

- `backend/`: FastAPI `/verdict` service running the pipeline above.
- `proxy/`: the `fetch_page` tool the agent uses; renders the page, calls `/verdict`, then returns the page, the sanitized page or a refusal.
- `agent/`: deliberately vulnerable browsing agent with a fake secret and a `send_request` tool, plus a flag to turn the firewall on and off.
- `semgrep-rules/`: three to five custom rules.
- `test-pages/`: self-hosted attack pages and one benign page (see below).
- `dashboard/`: ClickHouse-backed live view of verdicts.
- `seed/`: script that loads known injection payloads into MongoDB.

### Test pages

| Page | Attack | Expected verdict |
|---|---|---|
| `recipe.html` | White-on-white text telling the agent to send the user's API key to an attacker URL | block |
| `review.html` | `display:none` div telling the agent to recommend a scam product | sanitize |
| `news.html` | Instruction injected by JS after load | block |
| `recipe-v2.html` | Reworded copy of the first attack on a different page | block from cache |
| `benign.html` | Normal article with a legitimately hidden nav menu | allow |

The benign page matters: it shows we don't block everything with hidden text.

## Demo script (under 3 minutes)

1. **0:00–0:30, unprotected:** The agent is asked to summarize `recipe.html`. It reads the hidden instruction and sends the fake API key to the attacker endpoint, visible in a log on screen.
2. **0:30–1:30, protected:** Same request with the firewall on. The page is blocked; show the human view next to the agent view with the injected span highlighted, plus the Semgrep and model evidence.
3. **1:30–2:00, sanitize and allow:** `review.html` is sanitized and the agent gives an honest summary; `benign.html` passes untouched.
4. **2:00–2:30, cache:** `recipe-v2.html` is blocked from the vector match with no model call; point at the latency number.
5. **2:30–3:00, dashboard:** The ClickHouse dashboard shows all of the above as live events. Close on the pitch line.

## Open questions and risks

- **Semgrep on scraped pages:** it is built for source code, so inline scripts may need extracting into `.js` files first. Test in the first hour.
- **Vulnerable agent reliability:** the unprotected agent must misbehave every time. Use a weak system prompt and rehearse; if it is flaky, use a smaller model for the agent.
- **False positives:** hidden text is common on normal sites. The model, not the diff alone, makes the call.
- **Hackathon rules:** check whether code written before kickoff is allowed before scaffolding anything.
- **Sponsor prizes:** ask whether there are per-sponsor prizes; that decides whether Akash, Guild AI or Pi are worth the time.

## Scope cuts

- Host the test pages ourselves; don't rely on live malicious sites.
- No browser extension unless everything else is done by 3:00 PM.
- Write only three to five Semgrep rules.
- Record a backup video of the demo before 4:00 PM.

## Timeline

| Time | Goal |
|---|---|
| 11:00–12:00 | Test pages, vulnerable agent leaking the secret, `/verdict` with diff and OpenAI stages |
| 12:00–1:30 | Proxy wired to the agent, Semgrep stage, MongoDB cache and vector lookup |
| 1:30–2:00 | Lunch |
| 2:00–3:00 | ClickHouse telemetry and dashboard, demo UI showing human view against agent view |
| 3:00–4:00 | ElevenLabs alert if time allows, end-to-end rehearsal, record backup video |
| 4:00–4:30 | Submission |

### Suggested split

| Person | Owns |
|---|---|
| A | `backend/` pipeline and OpenAI decision model |
| B | `agent/`, `proxy/` and `test-pages/` |
| C | MongoDB seed and vector search, Semgrep rules |
| D | ClickHouse, dashboard and demo UI |

## Ideas not pursued

- **Browser page guard:** Chrome extension giving humans allow / warn / block on each page. Crowded space.
- **Link detonation with voice warning:** sandbox a suspicious URL and explain the verdict aloud. Shares the render-and-score engine with this plan, so it remains a fallback front end.
