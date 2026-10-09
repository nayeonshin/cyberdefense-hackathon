"""Controlled target only: file the report with the team's own mock registrar."""
import requests

from .. import config
from . import Context, Outcome

LIVE_FLAG = None


def base_url() -> str:
    return config.get("MOCK_REGISTRAR_URL", "http://localhost:8099").rstrip("/")


def describe(ctx: Context) -> str:
    return f"file abuse ticket for {ctx.verdict.target_url} with the mock registrar"


def execute(ctx: Context) -> Outcome:
    response = requests.post(f"{base_url()}/abuse", timeout=10, json={
        "url": ctx.verdict.target_url,
        "event_id": ctx.verdict.event_id,
        "evidence_sha256": ctx.sha,
    })
    if response.status_code != 200:
        return Outcome("FAILED", detail=f"HTTP {response.status_code}: {response.text[:200]}")
    data = response.json()
    return Outcome("SENT", data["receipt_url"], f"ticket {data['ticket']}: {data['result']}")
