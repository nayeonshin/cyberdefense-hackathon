"""Rung 1: report the URL to Netcraft, which verifies it before acting on it."""
import requests

from .. import config
from ..evidence import defang
from . import Context, Outcome

LIVE_FLAG = "LIVE_NETCRAFT"
DEFAULT_ENDPOINT = "https://report.netcraft.com/api/v3/report/urls"


def describe(ctx: Context) -> str:
    return f"report {defang(ctx.verdict.target_url)} to Netcraft"


def execute(ctx: Context) -> Outcome:
    email = config.get("REPORTER_EMAIL")
    if not email:
        return Outcome("SKIPPED", detail="REPORTER_EMAIL not set")
    reason = (f"{ctx.verdict.threat_type}; {ctx.verdict.evidence}; "
              f"evidence sha256 {ctx.sha}")[:1000]
    response = requests.post(
        config.get("NETCRAFT_REPORT_URL", DEFAULT_ENDPOINT), timeout=20,
        json={"email": email, "reason": reason, "urls": [{"url": ctx.verdict.target_url}]})
    if response.status_code != 200:
        return Outcome("FAILED", detail=f"HTTP {response.status_code}: {response.text[:200]}")
    uuid = response.json().get("uuid", "")
    proof = f"https://report.netcraft.com/submission/{uuid}" if uuid else ""
    return Outcome("SENT", proof, f"submission {uuid}")
