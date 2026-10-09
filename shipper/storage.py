import json
import os
import tempfile
import time
from pathlib import Path


def read_json(path, default=None):
    path = Path(path)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def write_json(path, value):
    """Atomic replacement so UI readers never see half a write."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, default=str)
            handle.flush()
            os.fsync(handle.fileno())
        # Windows readers / antivirus can briefly hold a destination without
        # FILE_SHARE_DELETE. Keep the old valid file while waiting for the lock.
        for attempt in range(10):
            try:
                os.replace(temporary, path)
                break
            except PermissionError:
                if attempt == 9:
                    raise
                time.sleep(min(0.02 * 2 ** attempt, 0.4))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_jsonl(path):
    path = Path(path)
    if not path.exists():
        return []
    result = []
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError:
            if index == len(lines) - 1 and not line.endswith("\n"):
                break  # writer has not finished its last record yet
            raise
    return result
