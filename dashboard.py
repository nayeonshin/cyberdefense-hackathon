"""Read-only presentation: importing this module never starts a worker."""
import time
from datetime import datetime, timezone
from urllib.parse import urlencode
import pandas as pd
import streamlit as st
from shipper.data import make_source
from shipper.model import defang, parse_time, public_proof, receipt_label, scan_label
from shipper.settings import Settings
from shipper.storage import read_json

st.set_page_config(page_title="Takedown Orchestrator", page_icon="🛡️", layout="wide")
st.markdown("""<style>
.block-container{max-width:1440px;padding-top:3.2rem}
[data-testid="stMetric"]{background:#102438;border:1px solid #294257;border-radius:12px;padding:20px}
[data-testid="stMetricValue"]{color:#75e3c3;font-variant-numeric:tabular-nums}
h1{letter-spacing:-1.4px} [data-testid="stCaptionContainer"]{color:#9fb3c8}
[data-testid="stExpander"]{border-color:#294257}
</style>""", unsafe_allow_html=True)  # constant CSS only; never interpolate evidence
settings = Settings.from_env()
st.caption("CYBERDEFENSE HACKATHON  /  OBSERVE → VERIFY → ACT")
st.title("Takedown Orchestrator")
st.write("An evidence trail from the first signal to the final action.")
if settings.source == "fixtures":
    st.warning("Simulated data — dashboard preview only. These are supplied examples, not live scans or dispatched reports.", icon="🧪")
elif settings.mode == "controlled":
    st.info("Controlled demonstration — team-owned harmless target and a private mock registrar. External reporting is disabled.", icon="🛡️")
else:
    st.info("Read-only preview — real data may be connected, but this runtime does not execute actions.")

with st.sidebar:
    st.header("Operations")
    st.caption("RUN")
    st.code(settings.run_id, language=None)
    st.caption(f"Source: {settings.source} · Refresh: 2 seconds")
    st.divider()
    st.subheader("Integration evidence")
    st.write("ClickHouse · event and action storage")
    st.write("Semgrep · findings from Member 2")
    st.write("Akash · deployment infrastructure")
    st.write("Guild AI · evaluation evidence from Member 2")
    st.caption("Listed integrations are architecture roles. Only verified runs count as sponsor usage.")
    deployment = read_json(settings.data_dir / "deployment.json", {})
    if deployment.get("dseq"):
        st.caption("Akash deployment identifier")
        st.code(str(deployment["dseq"]), language=None)
    else:
        st.caption("Akash deployment: not yet verified")


def load_snapshot():
    source = make_source(settings)
    try:
        started = time.perf_counter()
        events = source.get_events()
        receipts = source.get_receipts()
        metrics = source.get_metrics()
        return {"events": events, "receipts": receipts, "metrics": metrics,
                "query_ms": (time.perf_counter() - started) * 1000,
                "fetched_at": datetime.now(timezone.utc)}
    finally:
        if hasattr(source, "close"):
            source.close()


@st.fragment(run_every="2s")
def live_panels():
    error = None
    try:
        st.session_state["snapshot"] = load_snapshot()
    except Exception as exc:
        error = type(exc).__name__
    snapshot = st.session_state.get("snapshot")
    heartbeat = read_json(settings.run_dir / "heartbeat.json", {})
    supervisor = read_json(settings.run_dir / "supervisor.json", {})
    updated = parse_time(heartbeat.get("updated_at"))
    age = (datetime.now(timezone.utc) - updated).total_seconds() if updated else None
    status = heartbeat.get("status", "not connected")
    if age is None or age > 15:
        st.warning("Worker heartbeat unavailable or stale. The page cannot confirm pipeline activity.")
    elif status in {"degraded", "paused", "stopped"}:
        st.warning(f"Worker {status}: {heartbeat.get('detail', '')}")
    else:
        st.caption(f"WORKER {status.upper()}  ·  heartbeat {age:.0f}s ago  ·  {heartbeat.get('detail', '')}")
    if supervisor.get("missing") and settings.source != "fixtures":
        st.warning("Pending team handoff: " + ", ".join(supervisor["missing"]) + " command(s) are not configured.")
    if supervisor.get("status") == "failed":
        st.error("A supervised process exited: " + supervisor.get("process", "unknown"))
    pipeline = read_json(settings.run_dir / "pipeline.json", {})
    if pipeline.get("status") == "degraded":
        st.error("Team pipeline degraded: " + pipeline.get("detail", "integration unavailable"))
    elif pipeline:
        st.caption("TEAM PIPELINE · " + pipeline.get("detail", ""))
    if error:
        st.error(f"Data source unavailable ({error}). Showing the last successful snapshot, if any. No fixture fallback.")
    if snapshot is None:
        st.info("Waiting for data. Confirm ClickHouse credentials, the integration view, and the worker process.")
        return
    elapsed = (datetime.now(timezone.utc) - snapshot["fetched_at"]).total_seconds()
    st.caption(f"Last successful refresh: {snapshot['fetched_at']:%H:%M:%S} UTC · {elapsed:.0f}s ago · snapshot queries {snapshot['query_ms']:.0f} ms")
    metrics = snapshot["metrics"]
    cols = st.columns(5)
    for col, title, key in zip(cols, ["Ingested / minute", "Events", "Pending scans", "Detections", "Submitted actions"],
                               ["ingested_per_minute", "total_events", "pending_scans", "detected", "submitted_actions"]):
        col.metric(title, metrics[key])
    st.caption("Throughput uses ingestion time. Submitted actions count SENT receipts only; test-message sinks are excluded.")
    st.divider()
    records = snapshot["events"]
    receipts = snapshot["receipts"]
    event_rows = []
    for record in records:
        event, metadata = record["event"], record["metadata"]
        latest = next((r for r in receipts if r["event_id"] == event["event_id"]), None)
        event_rows.append({"Event": event["event_id"], "Target": defang(event["target_url"]),
            "Scan": scan_label(event, metadata), "Confidence": event["confidence_score"],
            "Action": receipt_label(latest) if latest else "Awaiting action"})
    st.subheader("Signal queue")
    if not records:
        st.info("No events in this run yet. Start Member 1's ingestion process to populate the queue.")
        return
    frame = pd.DataFrame(event_rows)
    def color_scan(value):
        return {"Threat detected": "color: #ff9f9f", "Scan failed": "color: #ff9f9f", "No rule matched": "color: #75e3c3", "Pending scan": "color: #f0d486"}.get(value, "")
    st.dataframe(frame.style.map(color_scan, subset=["Scan"]), hide_index=True, width="stretch",
        column_config={"Confidence": st.column_config.ProgressColumn(min_value=0, max_value=1, format="%.2f")})
    ids = [r["event"]["event_id"] for r in records]
    requested = st.query_params.get("event")
    if st.session_state.get("selected_event") not in ids:
        st.session_state["selected_event"] = requested if requested in ids else ids[0]
    selected = st.selectbox("Inspect an event", ids, key="selected_event")
    record = next(r for r in records if r["event"]["event_id"] == selected)
    event, metadata = record["event"], record["metadata"]
    left, right = st.columns([1.05, 1])
    with left:
        st.subheader("Scan evidence")
        st.caption(scan_label(event, metadata) + " · scanner: " + str(metadata.get("scanner") or "not reported"))
        st.code(event["evidence"] or "No completed scan evidence yet.", language=None, wrap_lines=True)
        st.caption("Target (defanged)")
        st.code(defang(event["target_url"]), language=None)
        st.caption("Timeline")
        st.write("Ingested: " + str(metadata.get("ingested_at") or "not reported"))
        st.write("Scan completed: " + str(metadata.get("scan_completed_at") or "pending"))
        with st.expander("Exact shared contract"):
            st.json(event)
    with right:
        st.subheader("Action receipts")
        matching = [r for r in receipts if r["event_id"] == selected]
        if not matching:
            st.info("No receipt yet. The dashboard does not initiate dispatch.")
        for index, receipt in enumerate(matching):
            with st.container(border=True):
                st.write(f"**{receipt_label(receipt)}** · {receipt['action']}")
                st.caption(str(receipt["created_at"]))
                st.text(receipt.get("detail", ""))
                proof = public_proof(receipt.get("proof_url", ""))
                if proof:
                    st.link_button("Open external proof", proof, key=f"proof-{selected}-{index}")
                else:
                    st.link_button("Open saved receipt view", "?" + urlencode({"event": selected}), key=f"receipt-{selected}-{index}")
                    st.caption("Saved receipt view; this is not an external provider confirmation.")
                with st.expander("Receipt details"):
                    st.json(receipt)
        check = read_json(settings.run_dir / "target-check.json", {})
        if check and event["target_url"] == settings.controlled_url:
            checked = parse_time(check.get("checked_at"))
            fresh = checked and (datetime.now(timezone.utc) - checked).total_seconds() < 15
            if fresh and check.get("started_at") == heartbeat.get("started_at"):
                st.caption(f"Controlled target: HTTP {check['http_status']} · checked {check['checked_at']}")
            else:
                st.warning("Previous target confirmation is historical; waiting for a fresh check.")
    st.caption("Probe-confirmed unavailability describes the observed HTTP/network result. It does not establish that an external provider performed a takedown.")


live_panels()
