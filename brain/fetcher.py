"""Download what a suspicious URL serves, as text, into a capture directory.

Nothing fetched here is ever rendered or executed. Run this inside WSL or the
container rather than directly on a laptop: the servers are hostile.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

TIMEOUT_S = 10
MAX_REDIRECTS = 3
MAX_BYTES = 2 * 1024 * 1024
MAX_EXTERNAL_SCRIPTS = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"
TEXT_TYPES = (
    "text/",
    "application/javascript",
    "application/x-javascript",
    "application/ecmascript",
    "application/json",
    "application/xhtml+xml",
    "application/x-sh",
    "application/x-shellscript",
)
MANIFEST = "manifest.json"


class FetchError(Exception):
    pass


@dataclass
class Capture:
    url: str
    directory: Path
    ok: bool = False
    error: str = ""
    final_url: str = ""
    # file name -> URL it came from
    files: dict[str, str] = field(default_factory=dict)


class _ScriptExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.inline: list[str] = []
        self.external: list[str] = []
        self._in_script = False
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag != "script":
            return
        attrs = dict(attrs)
        script_type = (attrs.get("type") or "").lower()
        if script_type and "javascript" not in script_type and script_type != "module":
            return
        if attrs.get("src"):
            self.external.append(attrs["src"])
        else:
            self._in_script = True
            self._buf = []

    def handle_data(self, data):
        if self._in_script:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self._in_script = False
            body = "".join(self._buf).strip()
            if body:
                self.inline.append(body)


def _check_host(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise FetchError(f"unsupported URL: {url}")
    if os.environ.get("BRAIN_ALLOW_PRIVATE") == "1":
        return
    # Feed-supplied URLs must not be able to reach our own network.
    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as exc:
        raise FetchError(f"DNS lookup failed: {exc}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise FetchError(f"refusing to fetch non-public address {ip}")


def _get(url: str) -> tuple[str, str, bytes]:
    """Return (final_url, content_type, body), following a few redirects by hand."""
    for _ in range(MAX_REDIRECTS + 1):
        _check_host(url)
        try:
            resp = requests.get(
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=TIMEOUT_S,
                allow_redirects=False,
                stream=True,
            )
        except requests.RequestException as exc:
            raise FetchError(f"request failed: {type(exc).__name__}") from exc
        with resp:
            if resp.is_redirect or resp.is_permanent_redirect:
                location = resp.headers.get("Location")
                if not location:
                    raise FetchError("redirect without Location")
                url = urljoin(url, location)
                continue
            if resp.status_code >= 400:
                raise FetchError(f"HTTP {resp.status_code}")
            content_type = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
            body = b""
            try:
                for chunk in resp.iter_content(64 * 1024):
                    body += chunk
                    if len(body) >= MAX_BYTES:
                        body = body[:MAX_BYTES]
                        break
            except requests.RequestException as exc:
                raise FetchError(f"read failed: {type(exc).__name__}") from exc
            return url, content_type, body
    raise FetchError("too many redirects")


def _is_text(content_type: str, body: bytes) -> bool:
    if b"\x00" in body[:2048]:
        return False
    return not content_type or content_type.startswith(TEXT_TYPES)


def _name_for(content_type: str, text: str) -> str:
    head = text.lstrip()[:200].lower()
    if "html" in content_type or head.startswith(("<!doctype", "<html")) or "<head" in head:
        return "page.html"
    if "javascript" in content_type or "ecmascript" in content_type:
        return "payload.js"
    if "sh" in content_type.split("/")[-1] or head.startswith("#!"):
        return "payload.sh"
    return "payload.txt"


def fetch_target(url: str, directory: str | Path) -> Capture:
    """Fetch url into directory. Never raises for network problems; check capture.ok."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    capture = Capture(url=url, directory=directory)
    try:
        final_url, content_type, body = _get(url)
        if not _is_text(content_type, body):
            raise FetchError(f"binary content ({content_type or 'unknown type'}), not scanned")
        text = body.decode("utf-8", errors="replace")
        name = _name_for(content_type, text)
        (directory / name).write_text(text, encoding="utf-8")
        capture.final_url = final_url
        capture.files[name] = final_url
        if name == "page.html":
            _extract_scripts(text, capture)
        capture.ok = True
    except FetchError as exc:
        capture.error = str(exc)
    write_manifest(capture)
    return capture


def _extract_scripts(html: str, capture: Capture) -> None:
    parser = _ScriptExtractor()
    try:
        parser.feed(html)
    except Exception:  # malformed HTML: keep whatever was parsed so far
        pass
    for i, body in enumerate(parser.inline):
        name = f"inline_{i}.js"
        (capture.directory / name).write_text(body, encoding="utf-8")
        capture.files[name] = capture.final_url
    for i, src in enumerate(parser.external[:MAX_EXTERNAL_SCRIPTS]):
        script_url = urljoin(capture.final_url, src)
        try:
            _, content_type, body = _get(script_url)
            if not _is_text(content_type, body):
                continue
        except FetchError:
            continue
        name = f"ext_{i}.js"
        (capture.directory / name).write_text(body.decode("utf-8", errors="replace"), encoding="utf-8")
        capture.files[name] = script_url


def write_manifest(capture: Capture) -> None:
    manifest = {
        "url": capture.url,
        "final_url": capture.final_url,
        "ok": capture.ok,
        "error": capture.error,
        "files": capture.files,
    }
    (capture.directory / MANIFEST).write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def load_capture(directory: str | Path) -> Capture:
    """Load a capture saved earlier (also used for the offline samples)."""
    directory = Path(directory)
    manifest = json.loads((directory / MANIFEST).read_text(encoding="utf-8"))
    return Capture(
        url=manifest.get("url", ""),
        directory=directory,
        ok=manifest.get("ok", True),
        error=manifest.get("error", ""),
        final_url=manifest.get("final_url", manifest.get("url", "")),
        files=manifest.get("files", {}),
    )
