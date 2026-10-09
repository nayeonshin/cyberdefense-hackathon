"""Fail visibly without losing the dashboard when status files are unavailable."""
from .model import parse_time
from .storage import read_json


def read_runtime_status(path):
    try:
        value = read_json(path, {})
        if not isinstance(value, dict):
            raise ValueError("Status must be an object")
        for key in ("status", "detail", "process", "started_at", "updated_at", "checked_at"):
            if key in value and not isinstance(value[key], str):
                raise ValueError("Invalid status field")
        for key in ("started_at", "updated_at", "checked_at"):
            if key in value and not parse_time(value[key]):
                raise ValueError("Invalid status time")
        if "missing" in value and (not isinstance(value["missing"], list)
                                   or not all(isinstance(x, str) for x in value["missing"])):
            raise ValueError("Invalid missing commands")
        return value, None
    except (OSError, ValueError, TypeError, OverflowError):
        # Exception text may contain private configuration. Only identify the file.
        return {}, f"Runtime status unavailable ({path.name}). Dependent progress cannot be confirmed."
