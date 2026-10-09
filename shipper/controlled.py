"""Persistent wrapper around Member 3's private, harmless registrar."""
import json
import re
import threading
from actor.mock_registrar_server import Handler, Registrar
from .storage import read_json, write_json


class PersistentHandler(Handler):
    def do_POST(self):
        # Only the local Actor uses this endpoint. Same event + evidence is idempotent.
        if self.path != "/abuse":
            return self._json(403, {"error": "reset and form collection disabled in the deployed demo"})
        length = int(self.headers.get("Content-Length") or 0)
        if length > 65536:
            return self._json(413, {"error": "report too large"})
        try:
            report = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeError):
            return self._json(400, {"error": "invalid JSON"})
        if not isinstance(report, dict) or not re.fullmatch(r"[0-9a-f]{64}", str(report.get("evidence_sha256", ""))):
            return self._json(400, {"error": "valid evidence hash required"})
        if report.get("url") != "http://localhost:8099/site" or not report.get("event_id"):
            return self._json(400, {"error": "not the configured controlled target"})
        with self.server.state_lock:
            for ticket in self.server.tickets.values():
                if ticket["event_id"] == report["event_id"] and ticket["evidence_sha256"] == report["evidence_sha256"]:
                    return self._json(200, ticket)
            ticket_id = f"T-{len(self.server.tickets) + 1:04d}"
            ticket = {**report, "ticket": ticket_id, "result": "site suspended", "controlled": True,
                      "receipt_url": f"http://localhost:8099/tickets/{ticket_id}"}
            self.server.tickets[ticket_id] = ticket
            self.server.suspended = True
            write_json(self.server.state_file, {"suspended": True, "tickets": self.server.tickets})
        self._json(200, ticket)


def start_registrar(run_dir):
    server = Registrar(("127.0.0.1", 8099))
    server.RequestHandlerClass = PersistentHandler
    server.state_file = run_dir / "registrar.json"
    server.state_lock = threading.Lock()
    state = read_json(server.state_file, {"tickets": {}, "suspended": False})
    server.tickets, server.suspended = state["tickets"], state["suspended"]
    thread = threading.Thread(target=server.serve_forever, name="private-registrar", daemon=True)
    thread.start()
    return server
