"""Fetch, scan and decide for one event.

    python -m brain.pipeline https://suspicious.example/login
    python -m brain.pipeline --event event.json
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import uuid
from datetime import datetime, timezone

from .decide import PENDING, decide
from .fetcher import fetch_target
from .scan import Finding, scan_capture


def new_event(target_url: str) -> dict:
    """An event as Member 1 would hand it over."""
    return {
        "event_id": f"evt-{uuid.uuid4().hex[:8]}",
        "target_url": target_url,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "semgrep_detected": None,
        "confidence_score": None,
        "evidence": "",
        "action_status": PENDING,
        "proof_url": "",
    }


def process_event(
    event: dict, listed_on_feed: bool = False, keep_dir: str | None = None
) -> tuple[dict, list[Finding]]:
    """Return (event with Member 2's fields filled in, findings)."""
    with tempfile.TemporaryDirectory(prefix="capture-") as tmp:
        capture = fetch_target(event["target_url"], keep_dir or tmp)
        findings = scan_capture(capture) if capture.ok else []
        return decide(event, capture, findings, listed_on_feed), findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect one suspicious URL and print the verdict event.")
    parser.add_argument("url", nargs="?", help="target URL")
    parser.add_argument("--event", help="path to an event JSON file in the shared contract")
    parser.add_argument("--listed-on-feed", action="store_true", help="the URL is confirmed by an independent feed")
    parser.add_argument("--keep", metavar="DIR", help="keep the capture in DIR instead of deleting it")
    parser.add_argument("--findings", action="store_true", help="also print the full findings list")
    args = parser.parse_args(argv)

    if args.event:
        with open(args.event, encoding="utf-8") as fh:
            event = json.load(fh)
    elif args.url:
        event = new_event(args.url)
    else:
        parser.error("give a URL or --event")

    result, findings = process_event(event, args.listed_on_feed, args.keep)
    if args.findings:
        result = {**result, "findings": [f.to_dict() for f in findings]}
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
