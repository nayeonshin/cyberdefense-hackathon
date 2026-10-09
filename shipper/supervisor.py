"""Supervise independent processes; browser sessions cannot create workers."""
import os
import signal
import subprocess
import sys
import time
from .model import now_iso
from .settings import Settings, command_from_env
from .storage import write_json


def main():
    settings = Settings.from_env()
    os.environ["SHIPPER_STARTED_AT"] = now_iso()
    commands = {"worker": [sys.executable, "-m", "shipper.worker"],
                "dashboard": [sys.executable, "-m", "streamlit", "run", "dashboard.py", "--server.address=0.0.0.0",
                              "--server.port=" + os.getenv("PORT", "8501"), "--server.headless=true"]}
    for name, env in (("ingestion", "INGEST_COMMAND_JSON"), ("scanner", "SCAN_COMMAND_JSON")):
        command = command_from_env(env)
        if command:
            commands[name] = command
    pipeline_command = command_from_env("TEAM_PIPELINE_COMMAND_JSON")
    if pipeline_command:
        if "ingestion" in commands or "scanner" in commands:
            raise ValueError("Use either the combined team adapter or separate team commands")
        commands["team_pipeline"] = pipeline_command
    children = {}
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    exit_code = 0
    try:
        for name, command in commands.items():
            children[name] = subprocess.Popen(command, start_new_session=os.name != "nt")
        while not stopping:
            for name, child in children.items():
                if child.poll() is not None:
                    write_json(settings.run_dir / "supervisor.json", {"status": "failed", "process": name,
                        "exit_code": child.returncode, "updated_at": now_iso()})
                    exit_code, stopping = 1, True
                    break
            if not stopping:
                try:
                    write_json(settings.run_dir / "supervisor.json", {"status": "running", "processes": list(children),
                        "updated_at": now_iso(), "missing": [] if "team_pipeline" in children else
                        [n for n in ("ingestion", "scanner") if n not in children]})
                except PermissionError:
                    print("Supervisor heartbeat temporarily locked; services continue running.", flush=True)
                time.sleep(1)
    finally:
        for child in children.values():
            if child.poll() is None:
                if os.name == "nt":
                    child.terminate()
                else:
                    os.killpg(child.pid, signal.SIGTERM)
        for child in children.values():
            try:
                child.wait(timeout=8)
            except subprocess.TimeoutExpired:
                if os.name == "nt":
                    child.kill()
                else:
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
