"""Fetch, scan and decide for one event.

    python -m brain.pipeline https://suspicious.example/login
    python -m brain.pipeline --event event.json
    python -m brain.pipeline https://a.example/ https://a.example/login https://b.example/
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from .decide import PENDING, decide
from .fetcher import fetch_target
from .scan import Finding, scan_capture, scan_captures

FETCH_WORKERS = 8


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


def process_events(
    events: list[dict], listed_on_feed: list[bool] | None = None
) -> list[tuple[dict, list[Finding]]]:
    """Batch form of process_event: fetch in parallel, then scan everything in one Semgrep run."""
    if not events:
        return []
    listed = listed_on_feed or [False] * len(events)
    with tempfile.TemporaryDirectory(prefix="capture-") as tmp:
        with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
            captures = list(
                pool.map(lambda pair: fetch_target(pair[1]["target_url"], Path(tmp) / str(pair[0])), enumerate(events))
            )
        fetched = [c for c in captures if c.ok]
        by_directory = dict(zip((c.directory for c in fetched), scan_captures(fetched)))
        results = []
        for event, capture, on_feed in zip(events, captures, listed):
            findings = by_directory.get(capture.directory, [])
            results.append((decide(event, capture, findings, on_feed), findings))
        return results


def summarize(events: list[dict]) -> dict:
    """Counts by action_status, plus the highest-confidence event in the batch."""
    counts: dict[str, int] = {}
    for event in events:
        counts[event["action_status"]] = counts.get(event["action_status"], 0) + 1
    worst = max(events, key=lambda e: e.get("confidence_score") or 0.0, default=None)
    return {
        "total": len(events),
        "by_status": counts,
        "highest_confidence": worst and {
            "event_id": worst["event_id"],
            "target_url": worst["target_url"],
            "confidence_score": worst["confidence_score"],
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect suspicious URLs and print the verdict events.")
    parser.add_argument("url", nargs="*", help="target URL; give several to scan them as one batch")
    parser.add_argument("--event", help="path to an event JSON file in the shared contract")
    parser.add_argument("--listed-on-feed", action="store_true", help="the URL is confirmed by an independent feed")
    parser.add_argument("--keep", metavar="DIR", help="keep the capture in DIR instead of deleting it")
    parser.add_argument("--findings", action="store_true", help="also print the full findings list")
    args = parser.parse_args(argv)

    if len(args.url) > 1:
        if args.event or args.keep:
            parser.error("--event and --keep take a single target")
        events = [new_event(url) for url in args.url]
        pairs = process_events(events, [args.listed_on_feed] * len(events))
        results = [
            {**event, "findings": [f.to_dict() for f in findings]} if args.findings else event
            for event, findings in pairs
        ]
        print(json.dumps({"results": results, "summary": summarize([e for e, _ in pairs])}, indent=2))
        return 0

    if args.event:
        with open(args.event, encoding="utf-8") as fh:
            event = json.load(fh)
    elif args.url:
        event = new_event(args.url[0])
    else:
        parser.error("give a URL or --event")

    result, findings = process_event(event, args.listed_on_feed, args.keep)
    if args.findings:
        result = {**result, "findings": [f.to_dict() for f in findings]}
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
