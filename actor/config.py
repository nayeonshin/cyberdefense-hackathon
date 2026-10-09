"""Settings from the environment and the repo-level .env file."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv(ROOT / ".env")


def get(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def flag(key: str) -> bool:
    return get(key, "0").lower() in ("1", "true", "yes")


def kill_switch() -> bool:
    """A STOP file in the repo root or ACTOR_STOP=1 halts every action."""
    return (ROOT / "STOP").exists() or flag("ACTOR_STOP")
