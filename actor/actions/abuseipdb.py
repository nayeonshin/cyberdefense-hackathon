"""Rung 1: report the hosting IP to AbuseIPDB. Policy keeps shared infrastructure out."""
import requests

from .. import config
from ..evidence import defang
from . import Context, Outcome

LIVE_FLAG = "LIVE_ABUSEIPDB"
ENDPOINT = "https://api.abuseipdb.com/api/v2/report"
CATEGORIES = {"phishing": "7", "malware": "20,21"}   # see abuseipdb.com/categories


def describe(ctx: Context) -> str:
    return f"report IP {ctx.recipient} to AbuseIPDB for hosting {defang(ctx.verdict.host)}"


def execute(ctx: Context) -> Outcome:
    key = config.get("ABUSEIPDB_API_KEY")
    if not key:
        return Outcome("SKIPPED", detail="ABUSEIPDB_API_KEY not set")
    comment = (f"Hosting {ctx.verdict.threat_type} at {defang(ctx.verdict.target_url)}. "
               f"{ctx.verdict.evidence} Evidence sha256 {ctx.sha}")[:1000]
    response = requests.post(
        ENDPOINT, timeout=20, headers={"Key": key, "Accept": "application/json"},
        data={"ip": ctx.recipient, "comment": comment,
              "categories": CATEGORIES.get(ctx.verdict.threat_type, "7")})
    if response.status_code != 200:
        return Outcome("FAILED", detail=f"HTTP {response.status_code}: {response.text[:200]}")
    score = response.json().get("data", {}).get("abuseConfidenceScore", "")
    return Outcome("SENT", f"https://www.abuseipdb.com/check/{ctx.recipient}",
                   f"abuse confidence score now {score}")
