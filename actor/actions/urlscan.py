"""Rung 1: public urlscan.io scan. It fetches the page for us and keeps a screenshot."""
import requests

from .. import config
from ..evidence import defang
from . import Context, Outcome

LIVE_FLAG = "LIVE_URLSCAN"
ENDPOINT = "https://urlscan.io/api/v1/scan/"


def describe(ctx: Context) -> str:
    return f"submit {defang(ctx.verdict.target_url)} to urlscan.io as a public scan"


def execute(ctx: Context) -> Outcome:
    key = config.get("URLSCAN_API_KEY")
    if not key:
        return Outcome("SKIPPED", detail="URLSCAN_API_KEY not set")
    response = requests.post(
        ENDPOINT, timeout=20,
        headers={"API-Key": key, "Content-Type": "application/json"},
        json={"url": ctx.verdict.target_url, "visibility": "public",
              "tags": ["takedown-orchestrator", ctx.verdict.threat_type]})
    if response.status_code != 200:
        return Outcome("FAILED", detail=f"HTTP {response.status_code}: {response.text[:200]}")
    data = response.json()
    return Outcome("SENT", data.get("result", ""), f"scan {data.get('uuid', '')} queued")
