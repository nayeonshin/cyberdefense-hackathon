"""Data for domain activity, threat-type and current scanner-verdict graphs.

    python -m brain.telemetry --output graph-data.json
    python -m brain.telemetry --output graph-data.json --plot graph-summary.svg

Plotting is optional: pip install -r requirements-plots.txt.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from ingest import connect_clickhouse, load_environment, table_name
from .clickhouse import ensure_events_schema, events_table_name


def graph_data(client) -> dict:
    ensure_events_schema(client)
    activity = client.query(f"""
        SELECT toUnixTimestamp(toStartOfHour(timestamp, 'UTC')) AS hour, domain,
               uniqExact(target_url) AS url_count
        FROM {table_name()} GROUP BY hour, domain ORDER BY hour, domain
    """).result_rows
    threats = client.query(f"""
        SELECT threat_type, uniqExact(event_id) AS event_count FROM {table_name()}
        GROUP BY threat_type ORDER BY event_count DESC, threat_type
    """).result_rows
    verdicts = client.query(f"""
        SELECT action_status, count() AS event_count FROM {events_table_name()} FINAL
        WHERE action_status IN ('VERIFIED', 'REJECTED', 'FETCH_FAILED')
        GROUP BY action_status ORDER BY action_status
    """).result_rows
    return {
        "domain_activity": [{"hour_utc": datetime.fromtimestamp(hour, timezone.utc).isoformat(),
                             "domain": domain, "url_count": count} for hour, domain, count in activity],
        "threat_types": [{"threat_type": kind, "event_count": count} for kind, count in threats],
        "scanner_verdicts": [{"action_status": status, "event_count": count} for status, count in verdicts],
    }


def plot_graphs(data, path, *, title="Threat feed and scanner"):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.ticker import MaxNLocator
    except ImportError as exc:
        raise RuntimeError("plot export needs: pip install -r requirements-plots.txt") from exc
    fig, axes = plt.subplots(1, 3, figsize=(16, 4.5), layout="constrained")
    fig.suptitle(title)
    for axis in axes:
        axis.yaxis.set_major_locator(MaxNLocator(integer=True))
    activity = data["domain_activity"]
    # Only the ten busiest domains are plotted; JSON retains every domain.
    totals = {}
    for row in activity:
        totals[row["domain"]] = totals.get(row["domain"], 0) + row["url_count"]
    hours = sorted({row["hour_utc"] for row in activity})
    times = [datetime.fromisoformat(hour) for hour in hours]
    for domain in sorted(totals, key=lambda name: (-totals[name], name))[:10]:
        counts = {row["hour_utc"]: row["url_count"] for row in activity if row["domain"] == domain}
        axes[0].plot(times, [counts.get(hour, 0) for hour in hours], marker="o", label=domain)
    axes[0].set(title="Domain activity", xlabel="Feed report hour (UTC)", ylabel="Distinct reported URLs")
    axes[0].set_ylim(bottom=0)
    if totals:
        axes[0].legend(fontsize="small")
    else:
        axes[0].text(0.5, 0.5, "No feed reports", ha="center", transform=axes[0].transAxes)
    for axis, key, field, title in (
        (axes[1], "threat_types", "threat_type", "Reported threat types"),
        (axes[2], "scanner_verdicts", "action_status", "Current scanner verdicts"),
    ):
        rows = data[key]
        axis.bar([row[field] for row in rows], [row["event_count"] for row in rows], color="#406ab3")
        axis.set(title=title, ylabel="Events")
        axis.tick_params(axis="x", labelrotation=20)
        if not rows:
            axis.text(0.5, 0.5, "No events", ha="center", transform=axis.transAxes)
        for index, row in enumerate(rows):
            axis.text(index, row["event_count"], str(row["event_count"]), ha="center", va="bottom")
    fig.autofmt_xdate(rotation=20)
    fig.savefig(path, dpi=160)
    plt.close(fig)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="graph-data.json")
    parser.add_argument("--plot", help="optional SVG, PNG or PDF path")
    args = parser.parse_args(argv)
    load_environment()
    client = connect_clickhouse()
    try:
        data = graph_data(client)
    finally:
        client.close()
    Path(args.output).write_text(json.dumps(data, indent=2), encoding="utf-8")
    if args.plot:
        plot_graphs(data, args.plot)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
