"""One module per channel. Each exposes LIVE_FLAG, describe(ctx) and execute(ctx)."""
from dataclasses import dataclass

from ..contract import Verdict
from ..enrich import Enrichment


@dataclass
class Context:
    verdict: Verdict
    enrichment: Enrichment
    bundle: dict
    sha: str
    recipient: str
    policy: dict
    action: str = ""


@dataclass
class Outcome:
    status: str          # SENT, SINK, SKIPPED or FAILED
    proof_url: str = ""
    detail: str = ""


def registry() -> dict:
    from . import abuseipdb, feed, mock_registrar, netcraft, urlscan, xarf_email
    return {
        "feed": feed,
        "urlscan": urlscan,
        "netcraft": netcraft,
        "abuseipdb": abuseipdb,
        "notify_host": xarf_email,
        "notify_registrar": xarf_email,
        "mock_registrar": mock_registrar,
    }
