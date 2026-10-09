"""Runtime configuration; credentials are never returned to the dashboard."""
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    source: str
    mode: str
    run_id: str
    data_dir: Path
    controlled_url: str
    poll_seconds: float
    recheck_seconds: float

    @classmethod
    def from_env(cls):
        # Reuse the Actor's dotenv loader, while leaving the Actor itself unchanged.
        from actor import config  # noqa: F401
        # Member 1 uses this second ignored file; existing process/.env values win.
        config._load_dotenv(config.ROOT / "clickhouse.env")
        run_id = os.getenv("RUN_ID", "development")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", run_id):
            raise ValueError("RUN_ID must contain only letters, digits, underscores, or hyphens")
        source = os.getenv("DATA_SOURCE", "fixtures")
        mode = os.getenv("RUN_MODE", "preview")
        if source not in {"fixtures", "files", "clickhouse", "backend"} or mode not in {"preview", "controlled"}:
            raise ValueError("Invalid DATA_SOURCE or RUN_MODE")
        if source == "fixtures" and mode != "preview":
            raise ValueError("Fixtures may only run in preview mode")
        if source == "backend" and mode != "preview":
            raise ValueError("Backend tables are read-only; use RUN_MODE=preview and the backend's own Actor")
        controlled_url = os.getenv("CONTROLLED_TARGET_URL", "http://localhost:8099/site")
        if controlled_url != "http://localhost:8099/site":
            raise ValueError("Controlled mode uses only the bundled private localhost:8099/site target")
        return cls(source, mode, run_id, Path(os.getenv("DATA_DIR", ".runtime")).resolve(),
                   controlled_url, max(1, float(os.getenv("POLL_SECONDS", "2"))),
                   max(1, float(os.getenv("RECHECK_SECONDS", "5"))))

    @property
    def run_dir(self):
        return self.data_dir / "runs" / self.run_id


def command_from_env(name):
    value = os.getenv(name, "")
    if not value:
        return None
    command = json.loads(value)
    if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
        raise ValueError(f"{name} must be a JSON array of command arguments")
    return command
