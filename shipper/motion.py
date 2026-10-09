"""Streamlit component assets are static; all event data travels as JSON."""
from pathlib import Path
import time

import streamlit as st

_HERE = Path(__file__).parent
_ASSETS = {kind: (_HERE / f"motion.{kind}").read_text(encoding="utf-8")
           for kind in ("html", "css", "js")}


def render_motion(data):
    # A stable key keeps the canvas and browser-only controls across fragment updates.
    # A new delivery stamp also enables a frontend watchdog if the socket disconnects.
    # Register in the active runtime, not at import time. Re-registering an
    # identical definition is idempotent, including across AppTest runtimes.
    component = st.components.v2.component("defense_motion", **_ASSETS)
    component(data={**data, "delivered_at": time.time()}, key="defense_motion", height="content")
