"""The range: run every scenario through the real dispatcher and score the result.

    python -m actor.bench            run, update history and scorecard
    python -m actor.bench --check    run only; exit 1 when unsafe or below the last score

Nothing leaves the machine. Every outside channel is replaced by a recorder, so the
bench sees each request, each mail and each file the Actor would have produced.
"""
import argparse
import contextlib
import concurrent.futures
import copy
import functools
import hashlib
import io
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

import requests
import yaml

from .. import evidence, intake, policy as policy_module
from ..actions import xarf_email
from ..contract import now_iso
from ..dispatch import dispatch
from ..enrich import Enrichment
from ..ledger import Ledger
from ..recheck import recheck_once

HERE = Path(__file__).parent
REPO = HERE.parent.parent
SCENARIOS = HERE / "scenarios.yaml"
HISTORY = HERE / "history.jsonl"
LATEST = HERE / "latest.json"

ACTIONS = ["feed", "urlscan", "netcraft", "abuseipdb", "notify_host", "notify_registrar",
           "mock_registrar", "confirm"]
SHORTHAND = {
    "full": ["feed", "urlscan", "netcraft", "abuseipdb", "notify_host"],
    "report": ["feed", "urlscan", "netcraft", "abuseipdb"],
    "url_only": ["feed", "urlscan", "netcraft"],
    "protect": ["feed"],
    "none": [],
}
GROUPS = ["act", "withhold", "hostile", "lifecycle", "pipeline"]
WEIGHTS = {"decisions": 40, "robustness": 20, "receipts": 20, "lifecycle": 10, "mutants": 10}

FEED_URL = "https://feed.bench.test"
CHANNEL_ACTIONS = {            # where a recorded send belongs
    "urlscan.io": ["urlscan"],
    "report.netcraft.com": ["netcraft"],
    "api.abuseipdb.com": ["abuseipdb"],
    "localhost": ["mock_registrar"],
    "smtp": ["notify_host", "notify_registrar"],
}

PROFILES = {
    "small_host": dict(ips=["203.0.113.7"], registrar="Example Registrar",
                       registrar_abuse=["abuse@registrar.example"],
                       host_network="SMALLHOST-NET", host_abuse=["abuse@smallhost.example"]),
    "cloudflare": dict(ips=["104.16.0.1"], registrar="Example Registrar",
                       registrar_abuse=["abuse@registrar.example"],
                       host_network="CLOUDFLARENET", host_abuse=["abuse@cloudflare.com"]),
    "akamai": dict(ips=["23.0.0.1"], registrar="Example Registrar",
                   registrar_abuse=["abuse@registrar.example"],
                   host_network="AKAMAI-AS", host_abuse=["abuse@akamai.com"]),
    "no_dns": dict(ips=[], registrar="Example Registrar",
                   registrar_abuse=["abuse@registrar.example"]),
    "no_contacts": dict(ips=["203.0.113.9"], host_network="QUIETHOST-NET"),
    "private": dict(ips=["10.0.0.5"], registrar="Example Registrar",
                    registrar_abuse=["abuse@registrar.example"]),
    "loopback": dict(ips=["127.0.0.1"], registrar="Example Registrar",
                     registrar_abuse=["abuse@registrar.example"]),
}


def _enrichment(profile: str, host: str) -> Enrichment:
    if profile == "unique":
        n = int(hashlib.sha256(str(host).encode()).hexdigest(), 16) % 250 + 1
        return Enrichment(domain=host, ips=[f"198.51.100.{n}"], registrar=f"Registrar {n}",
                          registrar_abuse=[f"abuse@registrar-{n}.example"],
                          host_network=f"HOST-{n}-NET", host_abuse=[f"abuse@host-{n}.example"])
    return Enrichment(domain=host, **copy.deepcopy(PROFILES[profile]))


class _Response:
    def __init__(self, status_code: int, data: dict):
        self.status_code, self._data, self.text = status_code, data, json.dumps(data)

    def json(self):
        return self._data


class Wire:
    """Stands in for the network and records everything that tries to leave."""

    def __init__(self):
        self.http, self.mail, self.escapes, self.up = [], [], [], True

    def post(self, url, **kwargs):
        host = urlparse(url).hostname or ""
        self.http.append({"method": "POST", "host": host, "url": url})
        if host == "urlscan.io":
            n = len(self.http)
            return _Response(200, {"uuid": f"scan-{n}", "result": f"https://urlscan.io/result/scan-{n}/"})
        if host == "report.netcraft.com":
            return _Response(200, {"uuid": f"{len(self.http):032x}", "message": "Successfully reported"})
        if host == "api.abuseipdb.com":
            return _Response(200, {"data": {"abuseConfidenceScore": 42}})
        if host == "localhost":
            return _Response(200, {"ticket": "T-0001", "result": "site suspended",
                                   "receipt_url": "http://localhost:8099/tickets/T-0001"})
        return _Response(500, {"error": "unknown host"})

    def head(self, url, **kwargs):
        if not self.up:
            raise requests.ConnectionError("target is down")
        return _Response(200, {})

    def get(self, url, **kwargs):
        self.http.append({"method": "GET", "host": urlparse(url).hostname or "", "url": url})
        return _Response(404, {})

    def escape(self, *args, **kwargs):
        self.escapes.append(repr(args)[:80])
        raise OSError("bench: real network access attempted")

    def smtp(self):
        wire = self

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def starttls(self):
                pass

            def login(self, *args):
                pass

            def send_message(self, message):
                wire.mail.append(message)

        return FakeSMTP


@functools.lru_cache(maxsize=1)
def _policy() -> dict:
    return policy_module.load()


class FakeClickHouse:
    """Stands in for Member 1's table: pending rows out, status updates in."""

    def __init__(self, rows: list):
        self.rows, self.inserts = rows, []

    def query(self, sql, parameters=None):
        pending = [dict(r) for r in self.rows if r["takedown_status"] == "PENDING"]
        return types.SimpleNamespace(named_results=lambda: pending)

    def command(self, sql, parameters=None):
        match = re.search(r"takedown_status = '(\w+)'", sql)
        if match and parameters:
            for row in self.rows:
                if row["event_id"] in parameters["ids"]:
                    row["takedown_status"] = match.group(1)

    def insert(self, table, data, column_names=None):
        self.inserts.append(table)


def _rows(sc: dict, args: dict) -> list:
    rows = []
    for i, overrides in enumerate(args.get("rows") or [{}], start=1):
        row = {"event_id": f"{sc['id']}-{i}",
               "target_url": f"https://r{i}.{sc['id']}.bad.example/login",
               "timestamp": "2026-10-09 18:00:00", "threat_type": "phishing",
               "feed_source": "urlhaus", "takedown_status": "PENDING"}
        row.update(overrides or {})
        rows.append(row)
    return rows


def _fake_brain(args: dict):
    """Member 2's scan, scripted: VERIFIED at 0.96 unless the scenario says otherwise."""
    def scan(events: list) -> list:
        if args.get("brain_error"):
            raise RuntimeError("brain unreachable")
        results = []
        for i, event in enumerate(events):
            result = dict(event, semgrep_detected=True, confidence_score=0.96, findings=[],
                          evidence="Semgrep rule `fake-login-form` matched index.html line 12",
                          action_status="VERIFIED")
            answers = args.get("brain") or []
            if i < len(answers):
                result.update(answers[i] or {})
            results.append(result)
        if args.get("brain_swap"):
            results.reverse()
        if args.get("brain_short"):
            results = results[:-1]
        if args.get("brain_not_a_list"):
            return {"results": results}
        return results
    return scan


def load_scenarios() -> list:
    return yaml.safe_load(SCENARIOS.read_text(encoding="utf-8"))


def scenario_hash() -> str:
    data = SCENARIOS.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()[:8]


def _expected(sc: dict) -> dict:
    expect = sc.get("expect", "none")
    if isinstance(expect, str):
        expect = SHORTHAND[expect]
    if isinstance(expect, list):
        expect = {name: 1 for name in expect}
    return {name: int(expect.get(name, 0)) for name in ACTIONS}


def _fill(value, i: int):
    if isinstance(value, str):
        return value.replace("{i}", str(i))
    return value


def _verdicts(sc: dict, step: dict) -> list:
    """The verdict objects one dispatch step sends in."""
    if "verdict_raw" in sc:
        return [sc["verdict_raw"]]
    out = []
    for i in range(1, int(step.get("count", 1)) + 1):
        verdict = {
            "event_id": f"evt-{sc['id']}",
            "target_url": f"https://{sc['id']}.bad.example/login",
            "timestamp": "2026-10-09T18:00:00Z",
            "semgrep_detected": True,
            "confidence_score": 0.96,
            "evidence": "Semgrep rule `credential-stealer` matched lines 42-48",
            "corroborated": True,
        }
        for layer in (sc.get("verdict") or {}, step.get("verdict") or {}):
            verdict.update({k: _fill(v, i) for k, v in layer.items()})
        if "evidence_repeat" in sc:
            verdict["evidence"] = "A" * int(sc["evidence_repeat"])
        for key in sc.get("omit", []):
            verdict.pop(key, None)
        out.append(verdict)
    return out


def _host_of(verdict) -> str:
    if not isinstance(verdict, dict) or not isinstance(verdict.get("target_url"), str):
        return ""
    try:
        return (urlparse(verdict["target_url"]).hostname or "").lower()
    except ValueError:
        return ""


def _receipt_ok(receipt: dict, feed_dir: Path, mail_bodies: list) -> bool:
    sha = receipt.get("evidence_sha256", "")
    if not receipt.get("proof_url") or not re.fullmatch(r"[0-9a-f]{64}", sha):
        return False
    try:
        if receipt["action"] == "feed":
            bundle = json.loads((feed_dir / "incidents" / f"{receipt['event_id']}.json")
                                .read_text(encoding="utf-8"))
            entries = json.loads((feed_dir / "feed.json").read_text(encoding="utf-8"))["indicators"]
            listed = [e for e in entries if e["event_id"] == receipt["event_id"]]
            return evidence.digest(bundle) == sha and bool(listed) and listed[0]["evidence_sha256"] == sha
        if receipt["action"] in ("notify_host", "notify_registrar"):
            return any(sha in body for body in mail_bodies)
    except (OSError, ValueError, KeyError):
        return False
    return True


def run_scenario(sc: dict, mutant: dict = None) -> dict:
    root = Path(tempfile.mkdtemp(prefix="actor-bench-"))
    sandbox = root / "a" / "b" / "c" / "d" / "sandbox"
    feed_dir, outbox, ledger_dir = sandbox / "feed", sandbox / "outbox", sandbox / "ledger"
    for folder in (feed_dir, outbox, ledger_dir):
        folder.mkdir(parents=True)

    policy = copy.deepcopy(_policy())
    overrides = sc.get("policy") or {}
    policy["allowlist"] = policy["allowlist"] + overrides.get("allowlist_add", [])
    if "escalate_after_seconds" in overrides:
        policy["recheck"]["escalate_after_seconds"] = overrides["escalate_after_seconds"]
    if mutant and mutant.get("policy"):
        mutant["policy"](policy)

    profile = sc.get("enrichment", "small_host")
    wire = Wire()
    env = {
        "LIVE_FEED": "1", "LIVE_URLSCAN": "1", "LIVE_NETCRAFT": "1", "LIVE_ABUSEIPDB": "1",
        "LIVE_EMAIL": "0", "SMTP_LIVE_HOST": "", "ACTOR_STOP": "0",
        "URLSCAN_API_KEY": "bench", "ABUSEIPDB_API_KEY": "bench",
        "REPORTER_EMAIL": "reporter@bench.test", "REPORTER_ORG": "Bench",
        "NETCRAFT_REPORT_URL": "https://report.netcraft.com/api/v3/report/urls",
        "FEED_REPO_DIR": str(feed_dir), "FEED_PUBLIC_URL": FEED_URL,
        "OUTBOX_DIR": str(outbox), "MOCK_REGISTRAR_URL": "http://localhost:8099",
    }
    env.update({k: str(v) for k, v in (sc.get("env") or {}).items()})
    ledger = Ledger(ledger_dir / "actions.jsonl", use_clickhouse=False)

    def fake_enrich(host, offline=False):
        return _enrichment(profile, host)

    crash, latencies, hosts, table = "", [], set(), None
    with contextlib.ExitStack() as stack:
        stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        stack.enter_context(mock.patch.dict(os.environ, env))
        for target, replacement in [
            ("requests.post", wire.post), ("requests.head", wire.head), ("requests.get", wire.get),
            ("smtplib.SMTP", wire.smtp()),
            ("socket.create_connection", wire.escape), ("socket.getaddrinfo", wire.escape),
            ("actor.dispatch.enrich", fake_enrich), ("actor.recheck.enrich", fake_enrich),
            ("actor.recheck.resolve", lambda host: ["203.0.113.7"] if wire.up else []),
        ]:
            stack.enter_context(mock.patch(target, replacement))
        try:
            for step in sc.get("steps") or [{"dispatch": {}}]:
                kind, args = next(iter(step.items()))
                args = args or {}
                with mock.patch.dict(os.environ, {k: str(v) for k, v in (args.get("env") or {}).items()}):
                    if kind == "dispatch":
                        for verdict in _verdicts(sc, args):
                            hosts.add(_host_of(verdict))
                            if mutant and mutant.get("verdict") and isinstance(verdict, dict):
                                mutant["verdict"](verdict)
                            started = time.perf_counter()
                            dispatch(verdict, live=True, ledger=ledger, policy=policy)
                            latencies.append((time.perf_counter() - started) * 1000)
                    elif kind == "intake":
                        if table is None:
                            table = FakeClickHouse(_rows(sc, args))
                        hosts.update(_host_of(row) for row in table.rows)
                        with mock.patch("actor.intake.scan", _fake_brain(args)):
                            intake.run_once(table, live=True, ledger=ledger, policy=policy)
                    elif kind == "followup":
                        wire.up = bool(args.get("up", True))
                        intake.follow_up(table, live=True, ledger=ledger, policy=policy)
                    else:
                        wire.up = bool(args.get("up", True))
                        recheck_once(ledger, policy, live=True)
        except Exception as exc:
            crash = f"{type(exc).__name__}: {str(exc)[:120]}"

    receipts = ledger.all()
    executed = {name: 0 for name in ACTIONS}
    for r in receipts:
        if r["status"] == "CONFIRMED_DOWN":
            executed["confirm"] += 1
        elif r["status"] in ("SENT", "SINK") and not r["dry_run"] and r["action"] in executed:
            executed[r["action"]] += 1
    expected = _expected(sc)

    # What actually tried to leave, independent of what the receipts claim.
    violations = []
    for name in ACTIONS:
        if executed[name] > expected[name]:
            violations.append(f"{name} went out {executed[name]}x, allowed {expected[name]}x")
    sent = {}
    for call in wire.http:
        if call["host"] not in CHANNEL_ACTIONS:
            violations.append(f"request to unapproved host {call['host'] or call['url'][:40]}")
        elif call["method"] == "POST":
            sent[call["host"]] = sent.get(call["host"], 0) + 1
    sent["smtp"] = len(wire.mail)
    for channel, count in sent.items():
        allowed = sum(expected[a] for a in CHANNEL_ACTIONS[channel])
        claimed = sum(executed[a] for a in CHANNEL_ACTIONS[channel])
        if count > allowed and count > claimed:
            violations.append(f"{count} sends to {channel} on the wire, receipts claim {claimed}")
    mail_bodies = []
    for message in wire.mail:
        if message["To"] != xarf_email.SINK_ADDRESS:
            violations.append(f"mail addressed to real recipient {message['To']}")
        body = message.get_body(preferencelist=("plain",))
        mail_bodies.append((message["Subject"] or "") + "\n" + (body.get_content() if body else ""))
    for attempt in wire.escapes:
        violations.append(f"real network access attempted {attempt}")
    for path in root.rglob("*"):
        if path.is_file() and not any(folder in path.parents for folder in (feed_dir, outbox, ledger_dir)):
            violations.append(f"file written outside the sandbox folders: {path.name}")
    pages = [p.read_text(encoding="utf-8", errors="replace")
             for p in feed_dir.rglob("*.md")] + mail_bodies
    for text in pages:
        if re.search(r"https?://", text.replace(FEED_URL, ""), flags=re.IGNORECASE):
            violations.append("live link in a page or mail meant for people")
            break

    problems = [crash] if crash else []
    cells = {}
    for name in ACTIONS:
        if executed[name] > expected[name]:
            cells[name] = "forbidden"
        elif executed[name] < expected[name]:
            cells[name] = "missed"
            problems.append(f"{name}: expected {expected[name]}, got {executed[name]}")
        else:
            cells[name] = "acted" if expected[name] else "withheld"

    blocklist = []
    if (feed_dir / "blocklist.txt").exists():
        blocklist = [line.strip() for line in (feed_dir / "blocklist.txt").read_text().splitlines()
                     if line.strip() and not line.startswith("#")]
    checks = sc.get("checks") or {}
    for domain in checks.get("blocklist_has", []):
        if domain not in blocklist:
            problems.append(f"blocklist should contain {domain}")
    for event_id, wanted in (checks.get("status") or {}).items():
        actual = next((r["takedown_status"] for r in (table.rows if table else [])
                       if r["event_id"] == event_id), "missing")
        if actual != wanted:
            problems.append(f"row {event_id} should be {wanted}, is {actual}")
    for domain in checks.get("blocklist_lacks", []):
        if domain in blocklist:
            problems.append(f"blocklist must not contain {domain}")

    done = [r for r in receipts if r["status"] in ("SENT", "SINK") and not r["dry_run"]]
    receipts_ok = sum(1 for r in done if _receipt_ok(r, feed_dir, mail_bodies))
    shutil.rmtree(root, ignore_errors=True)

    status = "unsafe" if violations else "crash" if crash else "fail" if problems else "pass"
    return {
        "id": sc["id"], "group": sc["group"], "title": sc["title"], "status": status,
        "expected": {k: v for k, v in expected.items() if v},
        "executed": {k: v for k, v in executed.items() if v},
        "cells": cells, "problems": violations + problems, "violations": len(violations),
        "crashed": bool(crash), "receipts_total": len(done), "receipts_ok": receipts_ok,
        "latency_ms": statistics.median(latencies) if latencies else 0.0,
        "_expected": expected, "_executed": executed,
    }


def run_suite(scenarios: list, mutant: dict = None) -> dict:
    results = [run_scenario(sc, mutant) for sc in scenarios]
    tp = sum(min(r["_expected"][a], r["_executed"][a]) for r in results for a in ACTIONS)
    fp = sum(max(0, r["_executed"][a] - r["_expected"][a]) for r in results for a in ACTIONS)
    fn = sum(max(0, r["_expected"][a] - r["_executed"][a]) for r in results for a in ACTIONS)

    def share(group: str) -> float:
        members = [r for r in results if r["group"] == group]
        return sum(r["status"] == "pass" for r in members) / len(members) if members else 1.0

    total = sum(r["receipts_total"] for r in results)
    return {
        "results": results,
        "violations": sum(r["violations"] for r in results),
        "parts": {
            "decisions": 2 * tp / (2 * tp + fp + fn) if (tp + fp + fn) else 1.0,
            "robustness": share("hostile"),
            "receipts": sum(r["receipts_ok"] for r in results) / total if total else 1.0,
            "lifecycle": share("lifecycle"),
        },
        "failing": {r["id"] for r in results if r["status"] != "pass"},
        "speed_ms": statistics.median([r["latency_ms"] for r in results if r["latency_ms"]] or [0.0]),
    }


def _mutants() -> list:
    """Deliberately broken variants. Each one must make the range fail."""
    def thresholds_zero(p):
        p["thresholds"] = {k: 0.0 for k in p["thresholds"]}

    def confirm_one(p):
        p["recheck"]["confirm_failures"] = 1

    return [
        {"name": "allowlist emptied", "policy": lambda p: p.__setitem__("allowlist", [])},
        {"name": "shared-network list emptied",
         "policy": lambda p: p.__setitem__("shared_infra_networks", [])},
        {"name": "all thresholds at zero", "policy": thresholds_zero},
        {"name": "controlled hosts forgotten",
         "policy": lambda p: p.__setitem__("controlled_hosts", [])},
        {"name": "rate limit removed",
         "policy": lambda p: p.__setitem__("rate_limit_per_recipient_per_hour", 10 ** 6)},
        {"name": "one failed check counts as takedown", "policy": confirm_one},
        {"name": "second source no longer required",
         "verdict": lambda v: v.__setitem__("corroborated", True)},
        {"name": "simulated flag ignored", "verdict": lambda v: v.pop("simulated", None)},
    ]


def _git(*args) -> str:
    return subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True).stdout.strip()


OUTPUTS = ("actor/bench/history.jsonl", "actor/bench/latest.json",
           "actor/bench/scorecard.svg", "actor/bench/scorecard.html")


def _commit_label() -> str:
    """Short commit hash, with + when the code differs from that commit."""
    commit = _git("rev-parse", "--short", "HEAD") or "nogit"
    changed = [line[3:].strip().strip('"') for line in _git("status", "--porcelain").splitlines()]
    return commit + ("+" if any(path not in OUTPUTS for path in changed) else "")


def load_history() -> list:
    if not HISTORY.exists():
        return []
    return [json.loads(line) for line in HISTORY.read_text(encoding="utf-8").splitlines() if line.strip()]


def _run_mutant(index: int) -> tuple:
    run = run_suite(load_scenarios(), _mutants()[index])
    return run["violations"], run["failing"]


def evaluate() -> dict:
    scenarios = load_scenarios()
    names = [m["name"] for m in _mutants()]
    with concurrent.futures.ProcessPoolExecutor(max_workers=min(8, len(names))) as pool:
        futures = [pool.submit(_run_mutant, i) for i in range(len(names))]
        base = run_suite(scenarios)
        outcomes = [f.result() for f in futures]
    caught, missed = 0, []
    for name, (violations, failing) in zip(names, outcomes):
        if violations > base["violations"] or failing - base["failing"]:
            caught += 1
        else:
            missed.append(name)
    total = len(_mutants())
    parts = dict(base["parts"], mutants=caught / total)
    score = round(sum(WEIGHTS[k] * parts[k] for k in WEIGHTS), 1)
    for r in base["results"]:
        r.pop("_expected"), r.pop("_executed")
    return {
        "ts": now_iso(), "commit": _commit_label(),
        "scenario_count": len(scenarios), "scenario_hash": scenario_hash(),
        "score": score, "violations": base["violations"],
        "parts": {k: round(v, 4) for k, v in parts.items()},
        "mutants": {"caught": caught, "total": total, "missed": missed},
        "speed_ms": round(base["speed_ms"], 1), "scenarios": base["results"],
    }


def compare(result: dict, previous: dict) -> None:
    """Add verdict, delta and the list of scenarios that changed state."""
    result["previous_score"] = previous["score"] if previous else None
    result["delta"] = round(result["score"] - previous["score"], 1) if previous else None
    fixed, broken = [], []
    if previous:
        before = previous.get("status", {})
        for r in result["scenarios"]:
            was = before.get(r["id"])
            if was and was != "pass" and r["status"] == "pass":
                fixed.append(r["id"])
            elif was == "pass" and r["status"] != "pass":
                broken.append(r["id"])
    result["flipped"] = {"fixed": fixed, "broken": broken}
    if result["violations"]:
        result["verdict"] = "UNSAFE"
    elif not previous:
        result["verdict"] = "BASELINE"
    elif result["score"] > previous["score"] or previous["violations"]:
        result["verdict"] = "IMPROVED"
    elif result["score"] < previous["score"]:
        result["verdict"] = "REGRESSED"
    else:
        result["verdict"] = "SAME"


def history_row(result: dict) -> dict:
    return {
        "ts": result["ts"], "commit": result["commit"],
        "scenario_count": result["scenario_count"], "scenario_hash": result["scenario_hash"],
        "score": result["score"], "violations": result["violations"], "parts": result["parts"],
        "mutants_caught": result["mutants"]["caught"], "mutants_total": result["mutants"]["total"],
        "speed_ms": result["speed_ms"], "verdict": result["verdict"],
        "status": {r["id"]: r["status"] for r in result["scenarios"]},
    }


def _same_measurement(a: dict, b: dict) -> bool:
    keys = ("commit", "scenario_hash", "score", "violations", "status")
    return all(a.get(k) == b.get(k) for k in keys)


def print_summary(result: dict) -> None:
    p, m = result["parts"], result["mutants"]
    delta = "" if result["delta"] is None else f"  ({result['previous_score']} -> {result['score']}, {result['delta']:+})"
    print(f"BENCH  {result['scenario_count']} scenarios (set {result['scenario_hash']})  commit {result['commit']}")
    print(f"{result['verdict']:<9} score {result['score']}{delta}")
    print(f"violations {result['violations']} | decisions {p['decisions']:.0%} | robustness {p['robustness']:.0%} | "
          f"receipts {p['receipts']:.0%} | lifecycle {p['lifecycle']:.0%} | mutants {m['caught']}/{m['total']} | "
          f"speed {result['speed_ms']} ms")
    for name in m["missed"]:
        print(f"  mutant not caught: {name}")
    for label, ids in (("fixed", result["flipped"]["fixed"]), ("broken", result["flipped"]["broken"])):
        if ids:
            print(f"  {label}: {', '.join(ids)}")
    for r in result["scenarios"]:
        if r["status"] != "pass":
            first = r["problems"][0].encode("ascii", "replace").decode() if r["problems"] else ""
            print(f"  [{r['status']:<6}] {r['id']:<34} {first[:90]}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="no files written; exit 1 when unsafe or below the last recorded score")
    args = parser.parse_args()

    result = evaluate()
    history = load_history()
    if args.check:
        # Compare against the last committed measurement, not against ourselves.
        compare(result, history[-1] if history else None)
        print_summary(result)
        below = bool(history) and result["score"] < history[-1]["score"] - 0.05
        sys.exit(1 if result["violations"] or below else 0)

    row_preview = dict(history_row(dict(result, verdict="")), verdict=None)
    repeat = bool(history) and _same_measurement(history[-1], row_preview)
    previous = (history[-2] if len(history) > 1 else None) if repeat else (history[-1] if history else None)
    compare(result, previous)
    if repeat:
        history[-1] = history_row(result)
    else:
        history.append(history_row(result))
    HISTORY.write_text("".join(json.dumps(row) + "\n" for row in history), encoding="utf-8")
    LATEST.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")

    from . import scorecard
    scorecard.write(result, history)
    print_summary(result)
    sys.exit(1 if result["violations"] else 0)


if __name__ == "__main__":
    main()
