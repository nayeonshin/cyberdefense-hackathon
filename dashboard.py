"""Read-only presentation: importing this module never starts a worker."""
import os
import time
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from urllib.parse import urlencode

import pandas as pd
import streamlit as st

from shipper.data import make_source
from shipper.model import current_confirmation, defang, parse_time, public_proof, scan_complete, scan_label
from shipper.presentation import (
    accept_queue_selection, metrics_html, receipt_state, resolve_selection,
    status_tone, timeline, timeline_html,
)
from shipper.settings import Settings
from shipper.runtime_status import read_runtime_status
from shipper.motion import render_motion
from shipper.motion_model import motion_state

st.set_page_config(page_title="Takedown Orchestrator", page_icon="🛡️", layout="wide")
st.html("<style>" + (Path(__file__).parent / "shipper/dashboard.css").read_text(encoding="utf-8") + "</style>")
settings = Settings.from_env()
st.title("Takedown Orchestrator")
if settings.source == "fixtures":
    st.warning("Simulated data — supplied examples only. No live scans or dispatched reports.", icon="🧪")
elif settings.source == "backend":
    st.info("Connected backend · Read-only view of ingestion, scanner verdicts, and Actor receipts. Backend workers run separately.")
elif settings.mode == "controlled":
    st.info("Controlled demo · Harmless team-owned target · Private mock registrar · External reporting disabled.", icon="🛡️")
else:
    st.info("Read-only preview · This runtime does not execute actions.")


def load_snapshot():
    source = make_source(settings)
    try:
        started = time.perf_counter()
        events, receipts, metrics = source.get_events(), source.get_receipts(), source.get_metrics()
        return {"events": events, "receipts": receipts, "metrics": metrics,
                "query_ms": (time.perf_counter() - started) * 1000,
                "fetched_at": datetime.now(timezone.utc)}
    finally:
        if hasattr(source, "close"):
            source.close()


def select_queue_event():
    accept_queue_selection(st.session_state)
    if st.session_state.get("selected_event"):
        st.query_params["event"] = st.session_state["selected_event"]


def label_html(label):
    return f'<span class="status-label {status_tone(label)}">{escape(label)}</span>'


def render_details(record, receipts, heartbeat, check):
    event, metadata = record["event"], record["metadata"]
    selected = event["event_id"]
    matching = sorted((r for r in receipts if r["event_id"] == selected),
                      key=lambda r: r.get("created_at", ""), reverse=True)
    owned_target = event["target_url"] == settings.controlled_url
    fresh_down = (owned_target and check.get("http_status") == 410
                  and current_confirmation(check, heartbeat, os.getenv("SHIPPER_STARTED_AT")))
    historical = settings.source == "backend" or (settings.mode == "controlled" and not fresh_down)
    st.subheader("Event investigation")
    st.text(selected)
    st.html(timeline_html(timeline(record, matching, historical=historical)))
    st.caption("TARGET · DEFANGED")
    st.code(defang(event["target_url"]), language=None, wrap_lines=True)
    st.subheader("Scan evidence")
    scan = scan_label(event, metadata)
    st.html(label_html(scan))
    completed = scan_complete(metadata)
    confidence = f"{event['confidence_score']:.2f}" if completed and scan != "Scan failed" else "Not available"
    st.caption(f"Scanner confidence: {confidence} · Scanner: {metadata.get('scanner') or 'not reported'}")
    if metadata.get("source") == "backend":
        st.caption("Scan time: " + metadata.get("scan_time_basis", "Not recorded") +
                   ". Actor outcome timestamps are not used as scan times.")
    st.code(event["evidence"] or "No completed scan evidence yet.", language=None, wrap_lines=True)
    with st.expander("Exact shared contract"):
        st.json(event)
    st.subheader("Action receipts")
    if not matching:
        st.info("No receipt yet. The dashboard does not initiate dispatch.")
    for index, receipt in enumerate(matching):
        with st.container(border=True):
            label = receipt_state(receipt, historical)
            st.html(label_html(label))
            st.text(receipt["action"])
            st.caption(str(receipt["created_at"]))
            st.text(receipt.get("detail", ""))
            proof = public_proof(receipt.get("proof_url", ""))
            st.link_button("View receipt" if index == 0 else "View receipt details",
                           proof or "?" + urlencode({"event": selected}),
                           type="primary" if index == 0 else "secondary",
                           key=f"receipt-{selected}-{index}")
            if not proof:
                st.caption("Saved receipt · Not an external provider confirmation.")
            with st.expander("Receipt data"):
                st.json(receipt)
    if check and owned_target:
        if fresh_down:
            st.caption(f"Fresh target check: HTTP {check['http_status']} · {check['checked_at']}")
        else:
            st.warning("Previous confirmation is historical; waiting for a fresh unavailable check.")


def render_run_details(snapshot, error, pipeline):
    with st.expander("Run details"):
        st.text("Scope: configured backend tables (all runs)" if settings.source == "backend" else f"Run: {settings.run_id}")
        st.text(f"Source: {settings.source} · Refresh: 2 seconds")
        if pipeline:
            st.text("Pipeline: " + pipeline.get("detail", pipeline.get("status", "Unknown")))
        deployment, deployment_error = read_runtime_status(settings.data_dir / "deployment.json")
        if deployment_error:
            st.error(deployment_error)
        st.text("Akash: " + (f"deployment {deployment['dseq']}" if deployment.get("dseq") else "deployment not verified"))
        runtime_scan = bool(snapshot and any(
            r["metadata"].get("scanner") == "semgrep" and scan_complete(r["metadata"])
            and scan_label(r["event"], r["metadata"]) != "Scan failed" for r in snapshot["events"]))
        st.text("Semgrep: " + ("completed scan recorded in this run" if runtime_scan else "no actual scan evidence in this run"))
        database_status = ("connected in this runtime" if snapshot and not error else "connection unavailable")
        st.text("ClickHouse: " + (database_status if settings.source in {"clickhouse", "backend"} else "not connected in this runtime"))
        st.markdown("[ClickHouse CI evidence — separate environment](https://github.com/nayeonshin/cyberdefense-hackathon/actions/runs/37982475135)")
        st.text("Guild AI: not used")
        if settings.source == "backend":
            st.caption("Latest 200 events shown; metrics cover all configured backend events. Confirmations are saved observations, not a fresh target probe.")
        st.caption("Runtime status and separate CI evidence are not interchangeable.")
        if snapshot:
            st.caption(f"Snapshot queries: {snapshot['query_ms']:.0f} ms")
        st.caption("Probe-confirmed unavailability is an observed HTTP/network result; it does not establish an external provider takedown.")


@st.fragment(run_every="2s")
def live_panels():
    context = (settings.source, settings.mode, settings.run_id, str(settings.data_dir),
               *(os.getenv(name, "") for name in ("CLICKHOUSE_HOST", "CLICKHOUSE_DATABASE",
                   "EVENTS_TABLE", "THREATS_TABLE", "VERDICTS_TABLE", "ACTIONS_TABLE")))
    if st.session_state.get("snapshot_context") != context:
        # A failed switch from fixtures to a backend must not relabel the old
        # sample snapshot as real data. Retain stale data only within one source.
        st.session_state.pop("snapshot", None)
        st.session_state.pop("selected_event", None)
        st.session_state["snapshot_context"] = context
    error = None
    try:
        st.session_state["snapshot"] = load_snapshot()
    except Exception as exc:
        error = type(exc).__name__
    snapshot = st.session_state.get("snapshot")
    statuses = []
    runtime_error = False
    for name in ("heartbeat.json", "supervisor.json", "pipeline.json", "target-check.json"):
        value, status_error = read_runtime_status(settings.run_dir / name)
        statuses.append(value)
        if status_error:
            runtime_error = True
            st.error(status_error)
    heartbeat, supervisor, pipeline, check = statuses
    updated = parse_time(heartbeat.get("updated_at"))
    age = (datetime.now(timezone.utc) - updated).total_seconds() if updated else None
    status = heartbeat.get("status", "not connected")
    boot, worker_start = parse_time(os.getenv("SHIPPER_STARTED_AT")), parse_time(heartbeat.get("started_at"))
    stale_worker = age is None or age < 0 or age > 15 or bool(boot and (not worker_start or worker_start < boot))
    if stale_worker:
        st.warning("Backend worker heartbeat is not exposed. Worker availability cannot be confirmed." if settings.source == "backend" else
                   "Worker heartbeat unavailable or stale. Pipeline activity cannot be confirmed.")
    elif status in {"degraded", "paused", "stopped"}:
        st.warning(f"Worker {status}: {heartbeat.get('detail', '')}")
    if supervisor.get("status") == "failed":
        st.error("A supervised process exited: " + supervisor.get("process", "unknown"))
    if supervisor.get("missing") and settings.source != "fixtures":
        st.warning("Pending team handoff: " + ", ".join(supervisor["missing"]) + " command(s) are not configured.")
    if pipeline.get("status") == "degraded":
        st.error("Team pipeline degraded: " + pipeline.get("detail", "integration unavailable"))
    if error:
        st.error(f"Data source unavailable ({error}). Showing the last successful snapshot, if any. No fixture fallback.")
    if snapshot is None:
        st.info("Waiting for data. Check the data source and team pipeline configuration.")
        render_motion(motion_state(None, [], simulated=settings.source == "fixtures", degraded=True))
        render_run_details(snapshot, error, pipeline)
        return
    elapsed = (datetime.now(timezone.utc) - snapshot["fetched_at"]).total_seconds()
    worker_label = "unavailable / stale" if stale_worker else f"{status} · heartbeat {age:.0f}s ago"
    st.caption(f"Worker {worker_label} · Last successful refresh {snapshot['fetched_at']:%H:%M:%S} UTC · {elapsed:.0f}s ago")
    records, receipts = snapshot["events"], snapshot["receipts"]
    degraded = bool(error or runtime_error or elapsed > 8 or supervisor.get("status") == "failed"
                    or pipeline.get("status") == "degraded"
                    or (settings.source != "fixtures" and (stale_worker or status != "running")))
    ids = [r["event"]["event_id"] for r in records]
    selected, disappeared = resolve_selection(ids, st.session_state.get("selected_event"), st.query_params.get("event"))
    st.session_state["selected_event"] = selected
    if disappeared:
        st.info("The selected event is no longer available. Showing the first available event." if ids else
                "The selected event is no longer available. The queue is empty.")
    if not records:
        st.info("No events in this run yet. Waiting for ingestion.")
        render_motion(motion_state(None, [], simulated=settings.source == "fixtures", degraded=degraded))
        st.html(metrics_html(snapshot["metrics"]))
        render_run_details(snapshot, error, pipeline)
        return

    # Reconcile the widget to the canonical event ID before each render. A callback
    # already consumed any click against the PREVIOUS rendered IDs.
    st.session_state["queue_event_ids"] = ids
    st.session_state["threat_queue"] = {"selection": {"rows": [ids.index(selected)], "columns": [], "cells": []}}
    fresh = check.get("http_status") == 410 and current_confirmation(check, heartbeat, os.getenv("SHIPPER_STARTED_AT"))
    selected_record = next(r for r in records if r["event"]["event_id"] == selected)
    historical = settings.source == "backend" or (settings.mode == "controlled" and not (fresh and selected_record["event"]["target_url"] == settings.controlled_url))
    render_motion(motion_state(selected_record, receipts, simulated=settings.source == "fixtures",
                               historical=historical, degraded=degraded))
    st.html(metrics_html(snapshot["metrics"]))
    st.caption("Throughput uses ingestion time. Submitted actions count SENT receipts only; saved test messages are excluded.")
    rows = []
    for record in records:
        event, metadata = record["event"], record["metadata"]
        matching = sorted((r for r in receipts if r["event_id"] == event["event_id"]),
                          key=lambda r: r.get("created_at", ""), reverse=True)
        historical = settings.source == "backend" or (settings.mode == "controlled" and not (fresh and event["target_url"] == settings.controlled_url))
        scan = scan_label(event, metadata)
        rows.append({"Event": event["event_id"], "Target": defang(event["target_url"]), "Scan": scan,
                     "Action": receipt_state(matching[0], historical) if matching else
                     ("Not applicable" if scan == "No rule matched" else "Awaiting action")})
    frame = pd.DataFrame(rows)
    def cell_color(value):
        return {"danger": "color: #a12b24", "pending": "color: #805500", "neutral": "color: #6d6c6b"}[status_tone(value)]

    with st.container(key="investigation"):
        queue, detail = st.columns([.9, 1.25], gap="medium")
        with queue, st.container(key="queue_panel"):
            st.subheader("Threat queue")
            st.caption("Select a row to inspect its evidence. Keyboard: arrow keys, then Shift+Space.")
            st.dataframe(frame.style.map(cell_color, subset=["Scan", "Action"]),
                         key="threat_queue", on_select=select_queue_event, selection_mode="single-row-required",
                         hide_index=True, width="stretch", height=min(440, 80 + len(rows) * 44), row_height=44,
                         column_order=["Event", "Scan", "Action", "Target"],
                         column_config={"Event": st.column_config.TextColumn(width="medium"),
                                        "Target": st.column_config.TextColumn(width="large")})
        with detail, st.container(key="event_details"):
            render_details(selected_record, receipts, heartbeat, check)
    render_run_details(snapshot, error, pipeline)


live_panels()
