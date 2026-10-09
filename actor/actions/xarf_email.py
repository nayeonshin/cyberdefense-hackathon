"""Rungs 2 and 3: abuse report by email, with a machine-readable XARF-style attachment.

Mail goes to the sink (Mailpit) unless LIVE_EMAIL=1 and a real SMTP relay is
configured. The message is always saved to outbox/ as an .eml file.
"""
import json
import smtplib
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

from .. import config
from ..contract import safe_id
from ..evidence import defang, for_people
from . import Context, Outcome

LIVE_FLAG = None          # always runs in live mode, but only into the sink by default
SINK_ADDRESS = "sink@takedown.test"


def describe(ctx: Context) -> str:
    return f"send abuse report for {defang(ctx.verdict.host)} to {ctx.recipient}"


def _xarf(ctx: Context) -> dict:
    return {
        "Version": "1",
        "ReporterInfo": {
            "ReporterOrg": config.get("REPORTER_ORG", "Takedown Orchestrator"),
            "ReporterOrgEmail": config.get("REPORTER_EMAIL", "reporter@takedown.test"),
        },
        "Disclosure": True,
        "Report": {
            "ReportClass": "Content",
            "ReportType": "Phishing" if ctx.verdict.threat_type == "phishing" else "Malware",
            "Date": ctx.verdict.timestamp,
            "Url": ctx.verdict.target_url,
            "Domain": ctx.verdict.host,
            "SourceIp": ctx.enrichment.ips[0] if ctx.enrichment.ips else "",
            "EvidenceSha256": ctx.sha,
            "Evidence": ctx.verdict.evidence,
        },
    }


def build(ctx: Context, to_address: str) -> EmailMessage:
    verdict = ctx.verdict
    sender = config.get("REPORTER_EMAIL", "reporter@takedown.test")
    message = EmailMessage()
    message["From"] = sender
    message["To"] = to_address
    message["Subject"] = (f"Abuse report: {verdict.threat_type} at "
                          f"{defang(verdict.host)} [{verdict.event_id}]")
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = make_msgid(domain="takedown.test")
    message["X-XARF"] = "PLAIN"
    message["X-Intended-Recipient"] = ctx.recipient
    feed = config.get("FEED_PUBLIC_URL").rstrip("/")
    lines = [
        "Hello,",
        "",
        f"we are reporting {verdict.threat_type} content hosted on infrastructure you are "
        "responsible for.",
        "",
        f"URL (defanged):  {defang(verdict.target_url)}",
        f"Domain:          {defang(verdict.host)}",
        f"IP address:      {', '.join(ctx.enrichment.ips) or 'did not resolve'}",
        f"Observed (UTC):  {verdict.timestamp}",
        f"Evidence:        {for_people(verdict.evidence)}",
        f"Evidence SHA-256: {ctx.sha}",
    ]
    if feed:
        lines.append(f"Evidence bundle: {feed}/incidents/{verdict.event_id}.json")
    lines += [
        "",
        "Please review the content and take it down if it violates your acceptable use policy.",
        "",
        "This report was generated automatically. The attached xarf.json carries the same "
        "data in machine-readable form. Replies to this address reach a person.",
        "",
        config.get("REPORTER_ORG", "Takedown Orchestrator"),
    ]
    message.set_content("\n".join(lines))
    message.add_attachment(json.dumps(_xarf(ctx), indent=2).encode("utf-8"),
                           maintype="application", subtype="json", filename="xarf.json")
    return message


def execute(ctx: Context) -> Outcome:
    live = config.flag("LIVE_EMAIL") and bool(config.get("SMTP_LIVE_HOST"))
    message = build(ctx, ctx.recipient if live else SINK_ADDRESS)
    outbox = Path(config.get("OUTBOX_DIR") or config.ROOT / "outbox")
    outbox.mkdir(parents=True, exist_ok=True)
    stage = "registrar" if ctx.action == "notify_registrar" else "host"
    name = safe_id(ctx.verdict.event_id)
    eml = outbox / f"{name}-{stage}.eml"
    eml.write_bytes(bytes(message))

    if live:
        with smtplib.SMTP(config.get("SMTP_LIVE_HOST"),
                          int(config.get("SMTP_LIVE_PORT", "587")), timeout=20) as smtp:
            smtp.starttls()
            smtp.login(config.get("SMTP_LIVE_USER"), config.get("SMTP_LIVE_PASSWORD"))
            smtp.send_message(message)
        return Outcome("SENT", eml.as_uri(), f"abuse report sent to {ctx.recipient}")

    host, port = config.get("SMTP_HOST", "localhost"), int(config.get("SMTP_PORT", "1025"))
    try:
        with smtplib.SMTP(host, port, timeout=5) as smtp:
            smtp.send_message(message)
        return Outcome("SINK", f"http://{host}:8025",
                       f"delivered to the mail sink, intended for {ctx.recipient}")
    except OSError:
        return Outcome("SINK", eml.as_uri(),
                       f"mail sink not running, saved to outbox, intended for {ctx.recipient}")
