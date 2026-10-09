"""Rung 0: publish the indicator to a public feed repository.

The repo holds feed.json (machine feed), blocklist.txt and hosts.txt (for DNS
blockers) and one evidence page per incident. Publishing is a git commit and push.
"""
import json
import re
import subprocess
from pathlib import Path

from .. import config
from ..contract import now_iso, safe_id
from ..evidence import defang, for_people, on_record
from ..policy import is_allowlisted
from . import Context, Outcome

LIVE_FLAG = "LIVE_FEED"

HEADER = ("# Takedown Orchestrator threat feed\n"
          "# Generated automatically. Entries are removed once the target is confirmed down.\n")


def repo_dir() -> Path:
    path = Path(config.get("FEED_REPO_DIR", "../threat-feed"))
    return path if path.is_absolute() else (config.ROOT / path).resolve()


def _git(repo: Path, *args) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)


def _load(repo: Path) -> list:
    path = repo / "feed.json"
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))["indicators"]


def render(repo: Path, entries: list) -> None:
    """Rewrite every generated file from the list of entries."""
    active = [e for e in entries if e["status"] == "active"]
    domains = sorted({e["domain"] for e in active if e["scope"] == "domain"})
    (repo / "feed.json").write_text(json.dumps(
        {"schema": "takedown-feed/1", "updated_at": now_iso(), "indicators": entries},
        indent=2) + "\n", encoding="utf-8")
    (repo / "blocklist.txt").write_text(
        HEADER + "".join(d + "\n" for d in domains), encoding="utf-8")
    (repo / "hosts.txt").write_text(
        HEADER + "".join(f"0.0.0.0 {d}\n" for d in domains), encoding="utf-8")


def _cell(text: str) -> str:
    return " ".join(for_people(text, 80).replace("|", "/").split())


def _fenced(text: str) -> str:
    """A code fence longer than any backtick run inside, so the text cannot break out."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return "\n".join([fence + "text", text, fence])


def _incident_page(ctx: Context) -> str:
    verdict, enrichment = ctx.verdict, ctx.enrichment
    return "\n".join([
        f"# {verdict.event_id}: {verdict.threat_type}",
        "",
        "| | |",
        "|---|---|",
        f"| URL (defanged) | `{defang(verdict.target_url)}` |",
        f"| Domain | `{defang(verdict.host)}` |",
        f"| Observed | {_cell(verdict.timestamp)} |",
        f"| Confidence | {verdict.confidence_score:.2f} |",
        f"| Hosting network | {_cell(enrichment.host_network) or 'unknown'} |",
        f"| Registrar | {_cell(enrichment.registrar) or 'unknown'} |",
        *([f"| On record | {on_record(ctx.bundle)} |"] if on_record(ctx.bundle) else []),
        f"| Evidence SHA-256 | `{ctx.sha}` |",
        "",
        "## Evidence",
        "",
        _fenced(for_people(verdict.evidence)) if verdict.evidence else "No evidence text supplied.",
        "",
        f"The full evidence bundle is in [{verdict.event_id}.json]({verdict.event_id}.json). "
        "Its SHA-256 over the canonical JSON equals the hash above and the hash quoted in "
        "every abuse report sent for this incident.",
        "",
    ])


def proof_url(repo: Path, event_id: str) -> str:
    public = config.get("FEED_PUBLIC_URL").rstrip("/")
    if public:
        return f"{public}/incidents/{event_id}.md"
    remote = _git(repo, "remote", "get-url", "origin").stdout.strip()
    if remote.startswith("https://github.com/"):
        return f"{remote.removesuffix('.git')}/blob/main/incidents/{event_id}.md"
    return (repo / "incidents" / f"{event_id}.md").as_uri()


def _commit_and_push(repo: Path, message: str) -> str:
    """Returns an error text, or an empty string on success."""
    if not (repo / ".git").exists():
        return ""   # a plain folder: files are written, nothing to push
    _git(repo, "add", "-A")
    commit = _git(repo, "commit", "-m", message)
    if commit.returncode != 0 and "nothing to commit" not in commit.stdout + commit.stderr:
        return f"git commit failed: {commit.stderr.strip()}"
    if not _git(repo, "remote").stdout.strip():
        return ""
    push = _git(repo, "push", "origin", "HEAD")
    return "" if push.returncode == 0 else f"git push failed: {push.stderr.strip()}"


def describe(ctx: Context) -> str:
    scope = "url" if is_allowlisted(ctx.verdict.host, ctx.policy) else "domain"
    return f"publish {scope} indicator for {defang(ctx.verdict.host)} to {repo_dir().name}"


def execute(ctx: Context) -> Outcome:
    repo = repo_dir()
    if not repo.exists():
        return Outcome("FAILED", detail=f"feed repo not found at {repo}")
    verdict = ctx.verdict
    entries = [e for e in _load(repo) if e["event_id"] != verdict.event_id]
    entries.append({
        "event_id": verdict.event_id,
        "url": verdict.target_url,
        "domain": verdict.host,
        "scope": "url" if is_allowlisted(verdict.host, ctx.policy) else "domain",
        "threat_type": verdict.threat_type,
        "confidence": verdict.confidence_score,
        "first_seen": verdict.timestamp,
        "published_at": now_iso(),
        "status": "active",
        "evidence_sha256": ctx.sha,
        "incident": f"incidents/{verdict.event_id}.md",
    })
    render(repo, entries)
    incidents = repo / "incidents"
    incidents.mkdir(exist_ok=True)
    name = safe_id(verdict.event_id)   # validated on arrival, cleaned again where the path is built
    (incidents / f"{name}.md").write_text(_incident_page(ctx), encoding="utf-8")
    (incidents / f"{name}.json").write_text(
        json.dumps(ctx.bundle, indent=2) + "\n", encoding="utf-8")
    error = _commit_and_push(repo, f"Add {verdict.event_id} ({verdict.threat_type})")
    if error:
        return Outcome("FAILED", detail=error)
    return Outcome("SENT", proof_url(repo, verdict.event_id), "indicator published")


def resolve(event_id: str) -> Outcome:
    """Rung 4: the target is down, so it leaves the blocklist."""
    repo = repo_dir()
    if not repo.exists():
        return Outcome("SKIPPED", detail="feed repo not found")
    entries = _load(repo)
    hit = [e for e in entries if e["event_id"] == event_id and e["status"] == "active"]
    if not hit:
        return Outcome("SKIPPED", detail="no active feed entry")
    for entry in hit:
        entry["status"] = "resolved"
        entry["resolved_at"] = now_iso()
    render(repo, entries)
    error = _commit_and_push(repo, f"Resolve {event_id} (confirmed down)")
    if error:
        return Outcome("FAILED", detail=error)
    return Outcome("SENT", proof_url(repo, event_id), "feed entry resolved")
