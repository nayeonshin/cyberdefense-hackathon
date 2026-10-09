#!/usr/bin/env python3
"""Preflight for Member 1. Answers one question: what is blocking you right now?

Read-only: creates nothing, writes nothing, mutates nothing. Never prints
the Auth-Key or the ClickHouse password.

    .venv/bin/python check_setup.py

Exit code 0 = nothing blocking, 1 = at least one blocker.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))
URLHAUS_PROBE = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
# Full column set created by `ingest.py` (six brief columns + event_id,
# feed_source, first_seen).
EXPECTED_COLUMNS = {
    "event_id", "target_url", "domain", "ip_address", "timestamp",
    "threat_type", "takedown_status", "feed_source", "first_seen",
}

OK = "  [ OK ]"
WARN = "  [WARN]"
FAIL = "  [FAIL]"

blockers: list[str] = []
warnings: list[str] = []


def say(line: str = "") -> None:
    print(line, flush=True)


def section(title: str) -> None:
    say()
    say(title)
    say("-" * len(title))


def read_env_file() -> dict[str, str]:
    """Minimal .env reader -- avoids importing dotenv before we know it exists."""
    values: dict[str, str] = {}
    for name in (".env", "clickhouse.env"):
        path = REPO / name
        if not path.is_file():
            continue
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            values.setdefault(key.strip(), val.strip())
    return values


# --------------------------------------------------------------------------- #
section("1. Python and dependencies")
# --------------------------------------------------------------------------- #

say(f"{OK} interpreter: {sys.executable}")
say(f"{OK} version: {sys.version.split()[0]}")

if sys.version_info < (3, 10):
    say(f"{FAIL} Python 3.10+ required for the `X | None` type syntax")
    blockers.append("Python is older than 3.10")

missing: list[str] = []
for module, package in (
    ("clickhouse_connect", "clickhouse-connect"),
    ("dotenv", "python-dotenv"),
    ("requests", "requests"),
):
    try:
        __import__(module)
        say(f"{OK} {package} importable")
    except ImportError:
        say(f"{FAIL} {package} NOT installed")
        missing.append(package)

if missing:
    blockers.append(
        f"missing dependencies: {', '.join(missing)} -- run "
        f"`{sys.executable} -m pip install -r requirements.txt`"
    )

# --------------------------------------------------------------------------- #
section("2. ClickHouse server")
# --------------------------------------------------------------------------- #

host = os.getenv("CLICKHOUSE_HOST", "localhost")
port = int(os.getenv("CLICKHOUSE_PORT", "8123"))

try:
    with socket.create_connection((host, port), timeout=3):
        say(f"{OK} TCP {host}:{port} reachable")
except OSError as exc:
    say(f"{FAIL} TCP {host}:{port} unreachable ({exc})")
    blockers.append("ClickHouse is not listening -- run `docker compose up -d`")

docker = shutil.which("docker")
if docker:
    try:
        out = subprocess.run(
            [docker, "ps", "--format", "{{.Names}}\t{{.Status}}"],
            capture_output=True, text=True, timeout=15,
        ).stdout
        found = [ln for ln in out.splitlines() if "threat-orchestrator-db" in ln]
        if found:
            say(f"{OK} container: {found[0]}")
        else:
            say(f"{WARN} container `threat-orchestrator-db` not in `docker ps`")
            warnings.append("ClickHouse container not running (or renamed)")
    except (subprocess.SubprocessError, OSError) as exc:
        say(f"{WARN} could not query docker: {exc}")
else:
    say(f"{WARN} docker CLI not found -- skipping container check")

# --------------------------------------------------------------------------- #
section("3. Credentials and live connectivity")
# --------------------------------------------------------------------------- #

env_file = read_env_file()
if env_file:
    say(f"{OK} env file parsed ({len(env_file)} keys)")
else:
    say(f"{WARN} no .env / clickhouse.env found")

pw = env_file.get("CLICKHOUSE_PASSWORD") or os.getenv("CLICKHOUSE_PASSWORD", "")
if pw:
    say(f"{OK} CLICKHOUSE_PASSWORD is set (not shown, {len(pw)} chars)")
else:
    say(f"{FAIL} CLICKHOUSE_PASSWORD is empty")
    blockers.append("CLICKHOUSE_PASSWORD not set")

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

if requests is not None and pw:
    try:
        r = requests.get(
            f"http://{host}:{port}/",
            params={"query": "SELECT version(), timezone()"},
            auth=("default", pw),
            timeout=5,
        )
        if r.status_code == 200:
            say(f"{OK} authenticated query: {r.text.strip()}")
            if "UTC" not in r.text:
                say(f"{WARN} server timezone is not UTC")
                warnings.append("ClickHouse timezone is not UTC; timestamps may drift")
        else:
            say(f"{FAIL} auth failed (HTTP {r.status_code}): {r.text.strip()[:120]}")
            blockers.append("ClickHouse rejected the credentials in clickhouse.env")
    except requests.RequestException as exc:
        say(f"{FAIL} could not query ClickHouse: {exc}")
        blockers.append(f"ClickHouse query failed: {exc}")

auth_key = env_file.get("URLHAUS_AUTH_KEY") or os.getenv("URLHAUS_AUTH_KEY", "")
if not auth_key:
    say(f"{FAIL} URLHAUS_AUTH_KEY is not set")
    say(f"{FAIL}   without it the feed returns HTTP 401 and ingest.py exits immediately")
    blockers.append(
        "URLHAUS_AUTH_KEY missing -- register at https://auth.abuse.ch/ "
        "and add it to clickhouse.env"
    )
elif requests is not None:
    try:
        r = requests.get(URLHAUS_PROBE, headers={"Auth-Key": auth_key}, timeout=20)
        if r.status_code == 200:
            payload = r.json()
            records = payload.get("urls") or []
            say(f"{OK} URLhaus authenticated, {len(records)} records returned")
            if records:
                sample = records[0]
                say(f"{OK} live sample keys: {sorted(sample)}")
                say(f"       date_added = {sample.get('date_added')!r}")
                say(f"       host       = {sample.get('host')!r}")
                reported = sample.get("date_added")
                try:
                    from ingest import parse_timestamp
                except ImportError as exc:
                    say(f"{WARN} could not import ingest.parse_timestamp ({exc})")
                    warnings.append("parser check skipped (ingest.py not importable)")
                else:
                    parsed = parse_timestamp(reported)
                    if parsed is None:
                        say(f"{FAIL} ingest.parse_timestamp cannot parse {reported!r} "
                            f"-- ingest.py would skip every row (it exits 3)")
                        blockers.append(
                            f"date_added format {reported!r} not handled by "
                            "ingest.parse_timestamp()"
                        )
                    else:
                        say(f"{OK} ingest.parse_timestamp handles it -> {parsed.isoformat()}")
                if sample.get("url_status"):
                    say(f"       url_status = {sample.get('url_status')!r} "
                        f"(not stored -- tells you whether the site is already dead)")
            else:
                say(f"{WARN} authenticated but the feed returned an empty array")
        elif r.status_code == 401:
            say(f"{FAIL} URLhaus 401 Unauthorized -- Auth-Key header not accepted")
            blockers.append("URLhaus rejected the request with 401")
        elif r.status_code == 403:
            say(f"{FAIL} URLhaus 403 -- Auth-Key invalid, revoked, or not activated")
            blockers.append("URLhaus rejected the Auth-Key with 403 (check auth.abuse.ch)")
        elif r.status_code == 429:
            say(f"{WARN} URLhaus 429 -- rate limited; key is probably fine, retry later")
            warnings.append("URLhaus rate limit hit during preflight")
        else:
            say(f"{WARN} URLhaus HTTP {r.status_code}: {r.text.strip()[:120]}")
    except requests.RequestException as exc:
        say(f"{WARN} could not reach URLhaus: {exc}")
        warnings.append(f"URLhaus unreachable from this machine: {exc}")

# --------------------------------------------------------------------------- #
section("4. Schema state (read-only)")
# --------------------------------------------------------------------------- #

if requests is not None and pw:
    try:
        r = requests.post(
            f"http://{host}:{port}/",
            params={"query": "DESCRIBE TABLE incoming_threats FORMAT TSV"},
            auth=("default", pw),
            timeout=10,
        )
        if r.status_code != 200:
            say(f"{WARN} incoming_threats does not exist yet (ingest.py creates it)")
        else:
            cols_types = dict(
                ln.split("\t")[:2] for ln in r.text.strip().splitlines() if ln.strip()
            )
            cols = list(cols_types)
            say(f"{OK} incoming_threats columns: {cols}")
            absent = sorted(EXPECTED_COLUMNS - set(cols))
            extra = sorted(set(cols) - EXPECTED_COLUMNS)
            if absent or extra:
                say(f"{FAIL} schema mismatch: missing={absent} unexpected={extra}")
                blockers.append(
                    f"schema does not match ingest.py (missing {absent}, unexpected "
                    f"{extra}) -- run `.venv/bin/python ingest.py --reset-schema`"
                )
            elif cols_types.get("timestamp") != "DateTime":
                say(f"{FAIL} `timestamp` is {cols_types.get('timestamp')}, expected DateTime")
                blockers.append("`timestamp` column is not DateTime -- run ingest.py --reset-schema")
            else:
                say(f"{OK} matches the Member 1 brief (all six brief columns, timestamp DateTime)")

            r2 = requests.post(
                f"http://{host}:{port}/",
                params={"query": "SELECT count(), countIf(takedown_status = 'PENDING') "
                                 "FROM incoming_threats FORMAT TSV"},
                auth=("default", pw), timeout=10,
            )
            if r2.status_code == 200:
                total, pending = (r2.text.strip().split("\t") + ["?"])[:2]
                say(f"{OK} current row count: {total} ({pending} PENDING)")
                if total == "0":
                    warnings.append("incoming_threats is empty -- run ingest.py")
    except requests.RequestException as exc:
        say(f"{WARN} schema check failed: {exc}")

# --------------------------------------------------------------------------- #
say()
say("=" * 68)
if blockers:
    say(f"BLOCKED -- {len(blockers)} item(s) must be fixed before the demo works:")
    for i, b in enumerate(blockers, 1):
        say(f"  {i}. {b}")
else:
    say("No blockers. The pipeline is ready for a live run.")
    say("  Next: .venv/bin/python ingest.py --dry-run")

if warnings:
    say()
    say(f"{len(warnings)} warning(s) -- not blocking:")
    for w in warnings:
        say(f"  - {w}")

say()
say("Decisions D1-D5 are resolved (MEMBER1_PLAN.md section 3).")
say("=" * 68)

sys.exit(1 if blockers else 0)
