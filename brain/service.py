"""HTTP wrapper so other members and the Guild agent can call the scanner.

    uvicorn brain.service:app --port 8002

Set BRAIN_API_KEY before exposing this on a public URL: /scan fetches whatever
URL it is given, so it must not be open to the internet.
"""
from __future__ import annotations

import hmac
import os
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .decide import PENDING
from .pipeline import process_event, process_events, summarize
from .scan import ScanError

app = FastAPI(title="Threat brain", version="0.1.0")


class Event(BaseModel):
    """The team's shared data contract. Unknown fields are passed through."""

    model_config = ConfigDict(extra="allow")

    event_id: str
    target_url: str
    timestamp: str
    semgrep_detected: Optional[bool] = None
    confidence_score: Optional[float] = None
    evidence: str = ""
    action_status: str = PENDING
    proof_url: str = ""
    # Not part of the contract: set when an independent feed also lists the URL.
    listed_on_feed: bool = False


class FindingOut(BaseModel):
    rule: str
    category: str
    weight: float
    file: str
    line: int
    end_line: int
    snippet: str


class ScanResult(Event):
    findings: list[FindingOut] = []


MAX_BATCH = 25


class BatchRequest(BaseModel):
    events: list[Event] = Field(min_length=1, max_length=MAX_BATCH)


class BatchResult(BaseModel):
    results: list[ScanResult]
    summary: dict


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    expected = os.environ.get("BRAIN_API_KEY")
    if not expected:
        return
    if not x_api_key or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.post(
    "/scan",
    operation_id="scan_url",
    summary="Fetch a suspicious URL, scan what it serves with Semgrep, and return the verdict",
    response_model=ScanResult,
    response_model_exclude={"listed_on_feed"},
    dependencies=[Depends(require_api_key)],
)
def scan(event: Event) -> dict:
    """Return the event with Member 2's fields filled in, plus a `findings` array."""
    payload = event.model_dump()
    listed = payload.pop("listed_on_feed")
    try:
        result, findings = process_event(payload, listed_on_feed=listed)
    except ScanError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {**result, "findings": [f.to_dict() for f in findings]}


@app.post(
    "/scan/batch",
    operation_id="scan_urls",
    summary="Scan up to 25 URLs in one call, such as the pages of one site, and return a verdict for each",
    response_model=BatchResult,
    dependencies=[Depends(require_api_key)],
)
def scan_batch(batch: BatchRequest) -> dict:
    """Results come back in request order, with counts by status in `summary`."""
    payloads = [event.model_dump() for event in batch.events]
    listed = [payload.pop("listed_on_feed") for payload in payloads]
    try:
        pairs = process_events(payloads, listed)
    except ScanError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {
        "results": [{**event, "findings": [f.to_dict() for f in findings]} for event, findings in pairs],
        "summary": summarize([event for event, _ in pairs]),
    }
