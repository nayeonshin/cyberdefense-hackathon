"""Build a page for checking the Actor's decisions by eye.

    python -m actor.review            writes actor/bench/review.html from the last stress run

The page shows one decision at a time: what the scanner said about a URL, what was on
record, and what the Actor did about it. Mark each one right or wrong with a key; the
wrong ones are collected as text to hand back.
"""
import json
import sys
from html import escape
from pathlib import Path

from . import history, policy as policy_module
from .contract import safe_id
from .evidence import defang
from .ledger import clickhouse_client

OUT = Path(__file__).parent / "bench" / "review.html"
PER_GROUP = 12
SENT = ("SENT", "SINK")

GROUPS = [
    ("hostile", "Hostile input", "A row no scanner should produce. Nothing may be done against the target named in it."),
    ("platform", "Shared platform", "A bad page on a platform many others use. Report the URL; never block or mail the platform."),
    ("full", "Mail to the host", "High confidence and a second source. The hosting provider gets an abuse report."),
    ("report", "Report only", "High confidence without a second source. Reporting platforms, no mail."),
    ("protect", "Feed only", "Confidence between 0.80 and 0.90. Published to the feed and nothing more."),
    ("low", "Too uncertain", "Confidence below 0.80. Nothing happens."),
    ("untouched", "Not verified", "The scanner rejected the page or could not fetch it. The Actor must not touch it."),
]


def collect(client) -> list:
    policy = policy_module.load()
    events = client.query(
        "SELECT event_id, target_url, action_status, proof_url, confidence_score, semgrep_detected "
        "FROM stress_events FINAL").named_results()
    feeds = dict(client.query("SELECT event_id, any(feed_source) FROM stress_threats GROUP BY event_id").result_rows)
    receipts = {}
    for row in client.query(
            "SELECT event_id, action, recipient, status, dry_run, detail, proof_url FROM stress_actions "
            "ORDER BY created_at").named_results():
        receipts.setdefault(row["event_id"], []).append(row)
    events = list(events)
    hosts = sorted({history._host(e["target_url"]) for e in events} - {""})
    on_record = {}
    for start in range(0, len(hosts), 2000):
        on_record.update(dict(client.query(
            "SELECT host, count() FROM threat_history WHERE host IN {hosts:Array(String)} GROUP BY host",
            parameters={"hosts": hosts[start:start + 2000]}).result_rows))

    cases = []
    for e in events:
        event_id, url = e["event_id"], e["target_url"]
        host = history._host(url)
        mine = receipts.get(event_id) or receipts.get(safe_id(event_id)) or []
        sent = [r for r in mine if r["status"] in SENT and not r["dry_run"]]
        actions = sorted({r["action"] for r in sent})
        confidence = e["confidence_score"]
        platform = bool(host) and policy_module.is_allowlisted(host, policy)
        if e["action_status"] in ("REJECTED", "FETCH_FAILED"):
            group = "untouched"
        elif event_id.startswith("hostile-") or event_id.startswith("..") or event_id == "dup-event":
            group = "hostile"
        elif platform:
            group = "platform"
        elif confidence is None or confidence < 0.80:
            group = "low"
        elif confidence < 0.90:
            group = "protect"
        elif "notify_host" in actions:
            group = "full"
        else:
            group = "report"
        shown = defang(url)
        cases.append({
            "id": event_id, "group": group,
            "url": shown[:220] + (f" ... ({len(url):,} characters)" if len(shown) > 220 else ""),
            "host": defang(host)[:120],
            "scanner": "VERIFIED" if group != "untouched" else e["action_status"],
            "detected": e["semgrep_detected"], "confidence": None if confidence is None else round(confidence, 2),
            "feed": feeds.get(event_id, ""), "on_record": int(on_record.get(host, 0)),
            "platform": platform, "outcome": e["action_status"],
            "sent": [{"action": r["action"], "to": defang(r["recipient"])[:80],
                      "how": "mail sink" if r["status"] == "SINK" else "recorded"} for r in sent],
            "held": [{"action": r["action"], "why": defang(r["detail"])[:200]}
                     for r in mine if r["status"] == "SKIPPED"],
        })
    return cases


def sample(cases: list) -> list:
    """Every hostile row, and the same number of each other kind, in a fixed order."""
    picked = []
    for key, _, _ in GROUPS:
        mine = sorted((c for c in cases if c["group"] == key), key=lambda c: c["id"])
        picked += mine if key == "hostile" else mine[:PER_GROUP]
    return picked


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Actor decision review</title>
<style>
:root{--surface:#fcfcfb;--tile:#f1f0ea;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;--grid:#e1e0d9;
--good:#0a7d0a;--crit:#c22f2f;--warn:#9a6a00}
@media (prefers-color-scheme: dark){:root{--surface:#1a1a19;--tile:#252523;--ink:#ffffff;--ink2:#c3c2b7;
--muted:#8f8d86;--grid:#34342f;--good:#4cc24c;--crit:#ef6b6b;--warn:#e0b040}}
*{box-sizing:border-box}
body{margin:0;background:var(--surface);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:920px;margin:0 auto;padding:24px 16px 80px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:32px 0 8px}
p{margin:0 0 12px;color:var(--ink2)}
.mono{font-family:ui-monospace,Consolas,Menlo,monospace;font-size:14px;overflow-wrap:anywhere}
.rules{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px;margin:16px 0}
.rules div{background:var(--tile);border-radius:6px;padding:10px 12px;font-size:14px;color:var(--ink2)}
.rules b{display:block;color:var(--ink)}
.bar{display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin:20px 0 8px;font-size:14px;color:var(--ink2)}
.bar b{color:var(--ink);font-variant-numeric:tabular-nums}
progress{flex:1;min-width:120px;height:8px;accent-color:var(--ink2)}
.card{border:1px solid var(--grid);border-radius:8px;padding:20px;margin:8px 0 12px}
.kind{font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.note{font-size:14px;color:var(--ink2);margin:2px 0 14px}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:20px}
@media (max-width:640px){.cols{grid-template-columns:1fr}}
.cols h3{font-size:13px;margin:0 0 6px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.06em}
dl{margin:0;display:grid;grid-template-columns:auto 1fr;gap:4px 12px;font-size:15px}
dt{color:var(--ink2)}dd{margin:0;font-variant-numeric:tabular-nums}
ul{margin:0;padding:0;list-style:none;font-size:15px}
li{padding:3px 0}
.did{color:var(--good);font-weight:600}.not{color:var(--muted)}
.why{display:block;font-size:13px;color:var(--ink2)}
.outcome{font-weight:700;font-size:17px;margin:0 0 6px}
.buttons{display:flex;gap:8px;flex-wrap:wrap;margin-top:18px}
button{font:inherit;padding:10px 16px;border-radius:6px;border:1px solid var(--grid);background:var(--tile);color:var(--ink);cursor:pointer}
button:hover{border-color:var(--ink2)}
button kbd{font:12px ui-monospace,Consolas,monospace;color:var(--muted);margin-left:6px}
.ok{border-color:var(--good)}.bad{border-color:var(--crit)}
.mark{font-weight:700}.mark.right{color:var(--good)}.mark.wrong{color:var(--crit)}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--grid);vertical-align:top}
th{color:var(--muted);font-weight:600}
tr.row{cursor:pointer}tr.row:hover{background:var(--tile)}
.wrap{overflow-x:auto}
textarea{width:100%;min-height:90px;font:13px ui-monospace,Consolas,monospace;background:var(--tile);color:var(--ink);border:1px solid var(--grid);border-radius:6px;padding:8px}
</style></head><body><main>
<h1>Actor decision review</h1>
<p>__SUMMARY__ Nothing on this page was sent: reports went to a recorder, mail to the mail sink. URLs are defanged.</p>
<div class="rules">
<div><b>Confidence 0.80 or more</b>publish to the public feed</div>
<div><b>0.90 or more</b>also urlscan, Netcraft, AbuseIPDB</div>
<div><b>0.95 or more and a second source</b>also mail the hosting provider. Second source: a trusted feed listing, or 3 or more URLs on record for the host</div>
<div><b>Shared platform</b>the URL may be reported; no blocklist entry, no IP report, no mail</div>
<div><b>Broken or internal input</b>nothing at all</div>
</div>
<div class="bar"><span>Case <b id="pos"></b></span><progress id="prog" value="0" max="1"></progress>
<span>right <b id="nright">0</b></span><span>wrong <b id="nwrong">0</b></span><span>open <b id="nopen">0</b></span></div>
<div class="card" id="card"></div>
<div class="buttons">
<button class="ok" id="right">Right<kbd>J</kbd></button>
<button class="bad" id="wrong">Wrong<kbd>F</kbd></button>
<button id="skip">Skip<kbd>S</kbd></button>
<button id="back">Back<kbd>B</kbd></button>
<button id="reset">Start over</button>
</div>
<h2>Marked wrong</h2>
<p>Add a note if you like, then copy the list and paste it into the chat.</p>
<textarea id="findings" readonly></textarea>
<div class="buttons"><button id="copy">Copy list</button></div>
<h2>All cases</h2>
<div class="wrap"><table><thead><tr><th>#</th><th>Kind</th><th>Target</th><th>Confidence</th><th>On record</th><th>Sent</th><th>Mark</th></tr></thead><tbody id="rows"></tbody></table></div>
</main>
<script>
const CASES = __CASES__;
const GROUPS = __GROUPS__;
const KEY = "actor-review-__RUN__";
let marks = {}, at = 0;
try { marks = JSON.parse(localStorage.getItem(KEY) || "{}"); } catch (e) {}
const $ = id => document.getElementById(id);
function el(tag, cls, text) { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = text; return n; }
function save() { try { localStorage.setItem(KEY, JSON.stringify(marks)); } catch (e) {} }
function pair(dl, k, v) { dl.append(el("dt", "", k), el("dd", "", v)); }
function show() {
  const c = CASES[at], card = $("card");
  card.textContent = "";
  card.append(el("div", "kind", GROUPS[c.group][0]), el("div", "note", GROUPS[c.group][1]), el("div", "mono", c.url || "(empty URL)"));
  const cols = el("div", "cols"); cols.style.marginTop = "16px";
  const left = el("div"), right = el("div");
  left.append(el("h3", "", "What was known"));
  const dl = el("dl");
  pair(dl, "Scanner", c.scanner + (c.detected === false ? ", nothing detected" : ""));
  pair(dl, "Confidence", c.confidence === null ? "missing" : c.confidence.toFixed(2));
  pair(dl, "Feed listing", c.feed || "none");
  pair(dl, "URLs on record for host", c.on_record.toLocaleString("en-US"));
  pair(dl, "Shared platform", c.platform ? "yes" : "no");
  pair(dl, "Event id", c.id.slice(0, 40));
  left.append(dl);
  right.append(el("h3", "", "What the Actor did"));
  right.append(el("div", "outcome", c.outcome === "PUBLISHED_TAKEDOWN" ? "Acted" : c.outcome === "WITHHELD" ? "Held everything back" : "Did not touch it (" + c.outcome + ")"));
  const ul = el("ul");
  c.sent.forEach(s => { const li = el("li"); li.append(el("span", "did", s.action), document.createTextNode(s.to ? "  to " + s.to : ""), el("span", "why", s.how)); ul.append(li); });
  c.held.forEach(h => { const li = el("li"); li.append(el("span", "not", h.action === "all" ? "refused" : "not " + h.action), el("span", "why", h.why)); ul.append(li); });
  if (!c.sent.length && !c.held.length) ul.append(el("li", "not", "no receipts for this event"));
  right.append(ul);
  cols.append(left, right); card.append(cols);
  const m = marks[c.id];
  if (m) card.append(el("div", "mark " + m.mark, "Marked " + m.mark + (m.note ? ": " + m.note : "")));
  $("pos").textContent = (at + 1) + " of " + CASES.length;
  $("prog").max = CASES.length; $("prog").value = at + 1;
  tally();
}
function tally() {
  const vals = CASES.map(c => marks[c.id]);
  const right = vals.filter(m => m && m.mark === "right").length, wrong = vals.filter(m => m && m.mark === "wrong").length;
  $("nright").textContent = right; $("nwrong").textContent = wrong; $("nopen").textContent = CASES.length - right - wrong;
  $("findings").value = CASES.filter(c => marks[c.id] && marks[c.id].mark === "wrong").map(c =>
    "WRONG " + c.id + " [" + GROUPS[c.group][0] + "] " + c.url.slice(0, 100) + " | confidence " + c.confidence + ", on record " + c.on_record +
    " | sent: " + (c.sent.map(s => s.action).join(", ") || "nothing") + (marks[c.id].note ? " | note: " + marks[c.id].note : "")).join("\\n")
    || "Nothing marked wrong. Reviewed " + (right + wrong) + " of " + CASES.length + ".";
  const body = $("rows"); body.textContent = "";
  CASES.forEach((c, i) => {
    const tr = el("tr", "row"); const m = marks[c.id];
    [String(i + 1), GROUPS[c.group][0], c.host || c.url.slice(0, 60), c.confidence === null ? "missing" : c.confidence.toFixed(2),
     c.on_record.toLocaleString("en-US"), c.sent.map(s => s.action).join(", ") || "nothing"].forEach((t, k) => tr.append(el("td", k === 2 ? "mono" : "", t)));
    tr.append(el("td", m ? "mark " + m.mark : "", m ? m.mark : ""));
    tr.onclick = () => { at = i; show(); window.scrollTo({top: 0}); };
    body.append(tr);
  });
}
function mark(value) {
  const c = CASES[at];
  let note = "";
  if (value === "wrong") note = prompt("What is wrong with this decision? (optional)") || "";
  marks[c.id] = {mark: value, note: note}; save(); step(1);
}
function step(d) { at = Math.max(0, Math.min(CASES.length - 1, at + d)); show(); }
$("right").onclick = () => mark("right"); $("wrong").onclick = () => mark("wrong");
$("skip").onclick = () => step(1); $("back").onclick = () => step(-1);
$("reset").onclick = () => { if (confirm("Clear all marks?")) { marks = {}; save(); at = 0; show(); } };
$("copy").onclick = () => { $("findings").select(); try { navigator.clipboard.writeText($("findings").value); } catch (e) { document.execCommand("copy"); } };
document.addEventListener("keydown", e => {
  if (e.target.tagName === "TEXTAREA" || e.ctrlKey || e.metaKey || e.altKey) return;
  const k = e.key.toLowerCase();
  if (k === "j" || k === "arrowright") mark("right");
  else if (k === "f") mark("wrong");
  else if (k === " " || k === "s" || e.code === "Space") { e.preventDefault(); step(1); }
  else if (k === "b" || k === "arrowleft") step(-1);
});
const firstOpen = CASES.findIndex(c => !marks[c.id]); at = firstOpen < 0 ? 0 : firstOpen;
show();
</script></body></html>
"""


def main() -> None:
    client = clickhouse_client()
    if client is None:
        sys.exit("CLICKHOUSE_HOST and CLICKHOUSE_PASSWORD must be set in .env")
    cases = collect(client)
    if not cases:
        sys.exit("stress_events is empty; run `python -m actor.stress` first")
    picked = sample(cases)
    counts = {key: sum(1 for c in cases if c["group"] == key) for key, _, _ in GROUPS}
    summary = (f"{len(picked)} decisions out of {len(cases):,} from the last stress run on ClickHouse: "
               f"every hostile row and {PER_GROUP} of each other kind.")
    data = json.dumps(picked, ensure_ascii=True).replace("</", "<\\/")
    groups = json.dumps({key: [title, note] for key, title, note in GROUPS})
    page = (PAGE.replace("__SUMMARY__", escape(summary)).replace("__CASES__", data)
            .replace("__GROUPS__", groups).replace("__RUN__", str(len(cases))))
    OUT.write_text(page, encoding="utf-8")
    print(f"{OUT.name}: {len(picked)} cases to review, from {len(cases)} events")
    for key, title, _ in GROUPS:
        print(f"  {title:<18} {counts[key]:>5} in the run")


if __name__ == "__main__":
    main()
