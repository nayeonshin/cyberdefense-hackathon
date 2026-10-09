"""Render a private SDL from runtime environment without printing secrets."""
import argparse
import os
from pathlib import Path
import yaml
from .settings import Settings

KEYS = ("CLICKHOUSE_HOST", "CLICKHOUSE_PORT", "CLICKHOUSE_USER", "CLICKHOUSE_PASSWORD", "CLICKHOUSE_DATABASE",
        "CLICKHOUSE_SECURE", "DATA_SOURCE", "RUN_MODE", "RUN_ID", "EVENTS_TABLE", "INGEST_COMMAND_JSON",
        "SCAN_COMMAND_JSON", "TEAM_PIPELINE_COMMAND_JSON", "CONTROLLED_TARGET_URL", "POLL_SECONDS", "RECHECK_SECONDS")


def render(image, output):
    if not image.startswith("ghcr.io/nayeonshin/cyberdefense-hackathon:") or "REPLACE" in image or image.endswith(":latest"):
        raise ValueError("Use the published commit-tagged GHCR image")
    Settings.from_env()  # validates mode before producing a manifest
    document = yaml.safe_load(Path("deploy.yaml").read_text())
    service = document["services"]["orchestrator"]
    service["image"] = image
    env = dict(item.split("=", 1) for item in service["env"])
    env.update({key: os.environ[key] for key in KEYS if key in os.environ})
    # Controlled demos can never enable third-party reporting through this renderer.
    env.update({key: "0" for key in ("LIVE_FEED", "LIVE_EMAIL", "LIVE_ABUSEIPDB", "LIVE_NETCRAFT", "LIVE_URLSCAN")})
    service["env"] = [f"{k}={v}" for k, v in env.items()]
    if Path(output).name != "deploy.private.yaml":
        raise ValueError("Output must be named deploy.private.yaml (gitignored)")
    Path(output).write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    print("Private SDL written. It may contain credentials; do not commit or share it.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", default="deploy.private.yaml")
    args = parser.parse_args()
    render(args.image, args.output)
