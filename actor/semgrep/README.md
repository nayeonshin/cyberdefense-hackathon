# Semgrep finding: path traversal in AI-generated code

**Where:** the Actor (`actor/`), written by an AI coding agent during this hackathon.
**Commit with the bug:** `a258b3b`. **Fixed in:** `0494e2a`, hardened further in the commit that adds this file.

## The vulnerability

The Actor publishes one page and one evidence file per incident. The file name was built
directly from `event_id`, a value that arrives from another pipeline stage:

```python
(incidents / f"{verdict.event_id}.md").write_text(...)
(incidents / f"{verdict.event_id}.json").write_text(...)
eml = outbox / f"{ctx.verdict.event_id}-{stage}.eml"
```

An `event_id` of `../../../escaped` writes outside the feed folder (CWE-22). The feed folder
is a git repository that the agent commits and pushes on its own, so whoever controls one
row of input could place files of their choosing next to it.

Reproduced on the baseline commit in a temporary folder:

```
status: SENT
   inside        a/b/feed/blocklist.txt
   inside        a/b/feed/feed.json
   inside        a/b/feed/hosts.txt
   OUTSIDE FEED  a/escaped.json
   OUTSIDE FEED  a/escaped.md
```

## What Semgrep found

| Scan | Rules that ran | Findings |
|---|---|---|
| Baseline `a258b3b` | 444 rules from seven registry rulesets: `p/default`, `p/python`, `p/security-audit`, `p/owasp-top-ten`, `p/cwe-top-25`, `p/secrets`, `p/bandit` | 1, and not the traversal: a notice that `feed.py` imports `subprocess` |
| Baseline `a258b3b` | Custom rule [untrusted-id-in-file-path.yaml](untrusted-id-in-file-path.yaml) | 3 (`feed.py` lines 128 and 129, `xarf_email.py` line 94) |
| Current code | The same seven rulesets, 465 rules on 42 files | 3, all the same `subprocess` import notice (`feed.py`, `bench/run.py`, `live.py`) |
| Current code | Same custom rule | 0 |

A clean scan says little until you know which rules ran, so the counts are part of the
result. 444 stock rules across seven rulesets ran over the vulnerable commit and none of them
saw the traversal: nothing in the code looks like a classic `open(request...)` sink, the
identifier is an attribute of a dataclass and the path is built with the `/` operator. The
custom rule describes exactly that shape, and it is the only one that fires.

The three notices on the current code were checked by hand. Each is `import subprocess`
(Bandit B404); every call passes git an argument list and none uses a shell, so no input
reaches a command line.

## Why it is interesting

The agent wrote careful code around this line: defanged URLs, hashed evidence, an allowlist,
a kill switch. It still trusted an identifier because it came from a teammate's stage rather
than from "the user". Input from another agent is still untrusted input.

The bug was first caught by the Actor's own benchmark (`actor/bench`, scenario
`path-traversal-id`). The Semgrep rule turns that one-off catch into a check that runs on
every future change.

## The fix

1. `event_id` is validated on arrival (`Verdict.from_dict` in `actor/contract.py`): 1 to 64
   characters of letters, digits, `.`, `_`, `-`, otherwise the verdict is refused.
2. Where a path is built, the identifier passes through `safe_id()` again, so the sink is
   safe even if a caller skips the validation.

## Reproduce

```bash
semgrep scan --config p/default --config p/python --config p/security-audit --config p/owasp-top-ten         --config p/cwe-top-25 --config p/secrets --config p/bandit actor   # prints "Ran N rules on M files"
semgrep --config actor/semgrep/untrusted-id-in-file-path.yaml actor      # current code: 0
git worktree add ../actor-baseline a258b3b
semgrep --config actor/semgrep/untrusted-id-in-file-path.yaml ../actor-baseline/actor   # 3
```
