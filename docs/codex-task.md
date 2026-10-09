# Task for Codex: extend Member 2's "Brain" (payload inspection and decision engine)

You are working in a hackathon repo on branch `timothy`. Another agent may be working in the same directory, so touch only the paths listed under "Scope". Read `PLAN.md` first (the "Member 2 plan" and "Contracts" sections are the specification), then `brain/README.md` for setup and usage.

Layers 1 to 3 and the `/scan` service are finished and tested. What remains is rule coverage for two missed samples and the Guild agent.

## Context

The team is building an Active Threat Takedown Orchestrator in four parts. This task is Member 2 only: take a suspicious URL, fetch what it serves, scan it with Semgrep, and return a verdict in the team's shared data contract. Members 1 (ClickHouse ingestion), 3 (takedown actions) and 4 (Akash, dashboard) are out of scope.

Shared contract, to be used exactly:

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

Member 2 receives events with `action_status: "PENDING"` and sets `semgrep_detected`, `confidence_score`, `evidence` and `action_status` to one of `VERIFIED`, `REJECTED` or `FETCH_FAILED`. Every other field passes through unchanged.

## What already exists

| Path | State |
|---|---|
| `brain/fetcher.py` | Done. Text-only HTTP fetch with redirect, size and private-address limits; extracts inline and external scripts into a capture directory with a `manifest.json`. |
| `brain/scan.py` | Done. Runs Semgrep over a capture, reads snippets from disk, drops same-site matches for rules marked `cross_origin_only`. |
| `brain/decide.py` | Done. Confidence = 1 − ∏(1 − weight) over distinct rules, +0.15 if listed on a feed, capped at 0.99; threshold 0.6. |
| `brain/pipeline.py` | Done. `process_event(event)` and a CLI (`python -m brain.pipeline <url>`). |
| `brain/service.py` | Done. FastAPI `POST /scan` and `GET /health`. Tested through FastAPI's test client; not yet started under `uvicorn`. |
| `brain/evaluate.py` | Done. Semgrep rules: 5 of 7 malicious detected, 0 of 6 benign flagged; regex baseline: 5 of 7 and 6 of 6. |
| `semgrep-rules/phishing.yaml` | Six rules, loading and matching. |
| `samples/malicious/` (7), `samples/benign/` (6) | Synthetic labelled captures. |
| `demo-sites/phish/`, `demo-sites/benign/` | Fictional phishing page and benign lookalike. |
| `tests/test_brain.py` | 7 tests, all passing (about a minute; each scan starts Semgrep). |
| `brain/README.md` | Done. Setup, CLI, service, settings, evaluation numbers. |
| `requirements.txt` | Done. Semgrep is deliberately not listed; it is installed separately. |
| `PLAN.md`, Member 2 section | Up to date with the built rules, weights and evaluation numbers. |

## Environment notes (Windows, learned the hard way)

- Semgrep must live in its **own** virtualenv. Installing FastAPI next to it upgrades `opentelemetry-api` and breaks Semgrep. On this machine a working Semgrep 1.180.0 is at `%TEMP%\sgv\Scripts\semgrep.exe` and a clean app venv (requests, FastAPI, pytest) is at `%TEMP%rv`; both are throwaway, so recreate them if they are gone. Point `SEMGREP_BIN` at the Semgrep executable.
- Create venvs at short paths; `pip install semgrep` fails on long Windows paths.
- Semgrep rejects float values in rule YAML, so `metadata.weight` is a quoted string.
- A Semgrep pattern containing a colon must be wrapped in single quotes.
- `extra.lines` in Semgrep's JSON needs a login, so snippets are read from the file.
- Long bash heredocs fail in this shell; write files with a Python script or the editor instead.
- Fetching the local demo sites needs `BRAIN_ALLOW_PRIVATE=1`.

## Tasks, in order

1. **Confirm the baseline.** Run `python -m pytest tests -q` with `SEMGREP_BIN` set; expect 7 passed. Run `python -m brain.evaluate`; expect the numbers above. If either differs, stop and report rather than fixing forward.
2. **Start the service under `uvicorn`.** `uvicorn brain.service:app --port 8002`, serve `demo-sites/` with `python -m http.server`, and `POST /scan` for both demo pages. Expect `VERIFIED` (0.95) for `phish/` and `REJECTED` (0.0) for `benign/`. This path has only been exercised through the test client so far.
3. **Improve coverage of the two missed samples without adding false positives.** `samples/malicious/obfuscated-eval` scores 0.4 and `samples/malicious/evasive` scores 0.0. Reasonable additions: a rule for bracket access with concatenated strings (`window["fe" + "tch"]`), and a rule for a decoded string (`atob`) used as a request URL. Weights go in `metadata.weight` as quoted strings. Re-run `python -m brain.evaluate`; the benign false-positive rate must stay at 0 of 6. Add one or two new benign samples that could plausibly trip the new rules, and a test for each new rule. Then update the rule table and numbers in `brain/README.md` and the Member 2 section of `PLAN.md`.
4. **Guild AI agent.** A "Verifier" agent under `agents/verifier/` that calls `/scan`, cross-checks the URL against threat feeds, and when Semgrep finds nothing on a suspicious page, reads the script and explains why; see "Layer 4" in `PLAN.md`. Use the Guild skills in `.claude/skills/` for the CLI workflow. This needs the user's Guild login and a public URL for `/scan`; if either is missing, write the agent code and stop there. The Guild MCP server failed to connect in the last session, so check it first.

## Scope

- **May edit:** `brain/`, `semgrep-rules/`, `samples/`, `demo-sites/`, `tests/`, `agents/verifier/`, `requirements.txt`, `.gitignore`, and the Member 2 section of `PLAN.md`.
- **Do not edit:** `docs/`, `.claude/`, `.mcp.json`, other sections of `PLAN.md`, or anything belonging to Members 1, 3 and 4.

## Rules

- Do not commit, push or create branches.
- Do not fetch real malicious URLs. Test only against `demo-sites/` and `samples/`.
- Do not send anything to third parties: no abuse reports, emails or public posts.
- Never render or execute fetched content.
- Keep the shared contract's field names and types exactly as shown.
- No new dependencies beyond `requests`, `fastapi`, `uvicorn`, `httpx` and `pytest` without saying why.

## Report back

- Test results: the pytest summary line before and after, and any test you changed and why.
- The `/scan` responses for both demo pages.
- The evaluation table before and after task 3.
- Files changed.
- Anything not done or not verified, stated plainly.
