"""Draw the bench result: scorecard.svg for the README and scorecard.html for a closer look."""
from html import escape
from pathlib import Path

HERE = Path(__file__).parent
W, PAD = 920, 24

ACTIONS = ["feed", "urlscan", "netcraft", "abuseipdb", "notify_host", "notify_registrar",
           "mock_registrar", "confirm"]
GROUPS = [("act", "should act"), ("withhold", "must not act"),
          ("hostile", "hostile input"), ("lifecycle", "lifecycle")]

STYLE = """
.card{--surface:#fcfcfb;--tile:#f1f0ea;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;
--grid:#e1e0d9;--good:#0ca30c;--warn:#fab219;--serious:#ec835a;--crit:#d03b3b}
@media (prefers-color-scheme: dark){.card{--surface:#1a1a19;--tile:#252523;--ink:#ffffff;
--ink2:#c3c2b7;--grid:#2c2c2a}}
.card text{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;fill:var(--ink)}
.bg{fill:var(--surface)}.tile{fill:var(--tile)}.t2{fill:var(--ink2)!important}
.tm{fill:var(--muted)!important}.good{fill:var(--good)}.ser{fill:var(--serious)}
.crit{fill:var(--crit)}.dot{fill:var(--grid)}.neutral{fill:var(--muted)}
.l-grid{stroke:var(--grid);stroke-width:1;fill:none}
.l-line{stroke:var(--ink2);stroke-width:2;fill:none;stroke-linejoin:round;stroke-linecap:round}
.l-ser{stroke:var(--serious);stroke-width:2;fill:none}
.l-crit{stroke:var(--crit);stroke-width:2;fill:none;stroke-linecap:round}
.l-white{stroke:#ffffff;stroke-width:3;fill:none;stroke-linecap:round;stroke-linejoin:round}
.ring{stroke:var(--surface);stroke-width:2}
"""

VERDICTS = {   # word -> (status class, white symbol drawn inside a 44px square)
    "IMPROVED": ("good", "M12 28 L22 16 L32 28"),
    "SAME": ("neutral", "M13 18 H31 M13 26 H31"),
    "BASELINE": ("neutral", "M14 22 H30"),
    "REGRESSED": ("ser", "M12 16 L22 28 L32 16"),
    "UNSAFE": ("crit", "M14 14 L30 30 M30 14 L14 30"),
}


def _text(x, y, content, size=12, cls="", anchor="start", weight="400") -> str:
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" font-weight="{weight}" '
            f'text-anchor="{anchor}" class="{cls}">{escape(str(content))}</text>')


def _pct(value: float) -> str:
    return f"{value * 100:.0f}%"


def _headline(result: dict) -> str:
    if result["violations"]:
        n = result["violations"]
        return f"{n} safety violation{'s' if n != 1 else ''}: not safe to run live"
    if result["delta"] is None:
        return "First measurement"
    if result["verdict"] == "SAME":
        return "No change since the last run"
    return f"Score went from {result['previous_score']} to {result['score']}"


def _spark(x, y, w, h, values) -> str:
    if len(values) < 2:
        return ""
    lo, hi = min(values), max(values)
    span = (hi - lo) or 1
    step = w / (len(values) - 1)
    points = [(x + i * step, y + h - (v - lo) / span * h) for i, v in enumerate(values)]
    path = " ".join(f"{'M' if i == 0 else 'L'}{px:.1f} {py:.1f}" for i, (px, py) in enumerate(points))
    lx, ly = points[-1]
    return f'<path d="{path}" class="l-line"/><circle cx="{lx:.1f}" cy="{ly:.1f}" r="3" class="t2 ring"/>'


def _tile(x, y, w, label, value, change, good_change, series) -> str:
    """change: numeric delta or None; good_change: whether that direction is an improvement."""
    out = [f'<rect x="{x:.1f}" y="{y}" width="{w:.1f}" height="86" rx="8" class="tile"/>',
           _text(x + 12, y + 22, label, 12, "t2"),
           _text(x + 12, y + 52, value, 23, weight="700")]
    if change is None:
        out.append(_text(x + 12, y + 72, "first run", 11, "tm"))
    elif change == 0:
        out.append(_text(x + 12, y + 72, "no change", 11, "tm"))
    else:
        cls = "good" if good_change else "ser"
        tri = (f"M{x + 12:.1f} {y + 71} l5 -8 l5 8 z" if change > 0
               else f"M{x + 12:.1f} {y + 63} l5 8 l5 -8 z")
        out.append(f'<path d="{tri}" class="{cls}"/>')
        out.append(_text(x + 26, y + 72, f"{change:+g}", 11, "t2"))
    out.append(_spark(x + w - 58, y + 62, 46, 14, series))
    return "".join(out)


def _matrix(result: dict, top: int) -> tuple:
    scenarios = []
    for key, _label in GROUPS:
        scenarios += [s for s in result["scenarios"] if s["group"] == key]
    label_w, gap = 122, 12
    avail = W - 2 * PAD - label_w - gap * (len(GROUPS) - 1)
    pitch = min(13.0, avail / max(1, len(scenarios)))
    cell = pitch - 2
    row_h = 14
    out = [_text(PAD, top, "Every scenario against every action", 13, weight="700")]

    # legend
    lx, ly = W - PAD - 520, top - 9
    legend = [("acted", "sent, as required"), ("withheld", "held back, as required"),
              ("missed", "should have sent"), ("forbidden", "must not have sent")]
    for state, words in legend:
        out.append(_cell(lx, ly, 9, state))
        out.append(_text(lx + 14, top, words, 11, "t2"))
        lx += 26 + len(words) * 5.9
    top += 22

    x = PAD + label_w
    columns = {}
    for key, label in GROUPS:
        members = [s for s in scenarios if s["group"] == key]
        passed = sum(s["status"] == "pass" for s in members)
        out.append(_text(x, top, f"{label} {passed}/{len(members)}", 11, "t2"))
        for s in members:
            columns[s["id"]] = x
            x += pitch
        x += gap
    grid_top = top + 8
    for row, action in enumerate(ACTIONS):
        y = grid_top + row * row_h
        out.append(_text(PAD + label_w - 10, y + cell * 0.5 + 4, action, 11, "t2", "end"))
        for s in scenarios:
            state = s["cells"].get(action, "withheld")
            tip = (f"{s['id']} / {action}: expected {s['expected'].get(action, 0)}, "
                   f"sent {s['executed'].get(action, 0)}")
            out.append(f"<g><title>{escape(tip)}</title>{_cell(columns[s['id']], y, cell, state)}</g>")
    bottom = grid_top + len(ACTIONS) * row_h
    for s in scenarios:
        if s["crashed"]:
            out.append(f'<rect x="{columns[s["id"]]:.1f}" y="{bottom + 1}" width="{cell:.1f}" '
                       f'height="4" class="ser"><title>{escape(s["id"])} crashed</title></rect>')
    if any(s["crashed"] for s in scenarios):
        out.append(f'<rect x="{PAD}" y="{bottom + 1}" width="9" height="4" class="ser"/>')
        out.append(_text(PAD + 14, bottom + 7, "bar under a column: the Actor crashed", 11, "t2"))
    return "".join(out), bottom + 16


def _cell(x, y, size, state) -> str:
    if state == "acted":
        return f'<rect x="{x:.1f}" y="{y:.1f}" width="{size:.1f}" height="{size:.1f}" rx="1.5" class="good"/>'
    if state == "missed":
        return (f'<rect x="{x + 1:.1f}" y="{y + 1:.1f}" width="{size - 2:.1f}" height="{size - 2:.1f}" '
                f'rx="1" class="l-ser"/>')
    if state == "forbidden":
        return (f'<path d="M{x:.1f} {y:.1f} l{size:.1f} {size:.1f} M{x + size:.1f} {y:.1f} '
                f'l{-size:.1f} {size:.1f}" class="l-crit"/>')
    half = size / 2
    return f'<circle cx="{x + half:.1f}" cy="{y + half:.1f}" r="1.3" class="dot"/>'


def _history(history: list, top: int) -> tuple:
    runs = history[-40:]
    out = [_text(PAD, top, "Score per run", 13, weight="700")]
    out.append(f'<circle cx="{W - PAD - 190}" cy="{top - 4}" r="4" class="good"/>')
    out.append(_text(W - PAD - 181, top, "safe run", 11, "t2"))
    out.append(f'<path d="M{W - PAD - 110} {top - 8} l8 8 m0 -8 l-8 8" class="l-crit"/>')
    out.append(_text(W - PAD - 96, top, "run with violations", 11, "t2"))
    x0, x1, y0, h = PAD + 34, W - PAD - 30, top + 14, 78
    for value in (0, 50, 100):
        y = y0 + h - value / 100 * h
        out.append(f'<path d="M{x0} {y:.1f} H{x1}" class="l-grid"/>')
        out.append(_text(x0 - 8, y + 4, value, 11, "tm", "end"))
    step = (x1 - x0) / max(1, len(runs) - 1) if len(runs) > 1 else 0
    points = [(x0 + i * step, y0 + h - r["score"] / 100 * h) for i, r in enumerate(runs)]
    if len(points) > 1:
        path = " ".join(f"{'M' if i == 0 else 'L'}{x:.1f} {y:.1f}" for i, (x, y) in enumerate(points))
        out.append(f'<path d="{path}" class="l-line"/>')
    for (x, y), run in zip(points, runs):
        tip = f"{run['commit']}: score {run['score']}, {run['violations']} violations"
        if run["violations"]:
            mark = (f'<circle cx="{x:.1f}" cy="{y:.1f}" r="7" class="bg"/>'
                    f'<path d="M{x - 4:.1f} {y - 4:.1f} l8 8 m0 -8 l-8 8" class="l-crit"/>')
        else:
            mark = f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" class="good ring"/>'
        out.append(f"<g><title>{escape(tip)}</title>{mark}</g>")
    if points:
        x, y = points[-1]
        out.append(_text(x + 10, y + 4, runs[-1]["score"], 12, weight="700"))
    return "".join(out), y0 + h + 22


def svg(result: dict, history: list) -> str:
    cls, symbol = VERDICTS[result["verdict"]]
    parts, mutants = result["parts"], result["mutants"]
    prev = history[-2] if len(history) > 1 else None
    body = [f'<rect x="{PAD}" y="{PAD}" width="44" height="44" rx="10" class="{cls}"/>',
            f'<path d="{symbol}" transform="translate({PAD},{PAD})" class="l-white"/>',
            _text(PAD + 58, PAD + 21, result["verdict"], 22, weight="700"),
            _text(PAD + 58, PAD + 41, _headline(result), 13, "t2"),
            _text(W - PAD, PAD + 34, result["score"], 42, anchor="end", weight="700"),
            _text(W - PAD, PAD + 52, "out of 100", 11, "tm", "end"),
            _text(PAD, PAD + 72, f"{result['scenario_count']} scenarios (set {result['scenario_hash']})"
                  f"  |  commit {result['commit']}  |  {result['ts'][:16].replace('T', ' ')} UTC", 11, "tm")]

    def series(getter):
        return [getter(row) for row in history[-20:]]

    def change(now, getter, scale=1.0):
        return None if prev is None else round((now - getter(prev)) * scale, 1)

    tiles = [
        ("Safety violations", str(result["violations"]),
         change(result["violations"], lambda r: r["violations"]), False,
         series(lambda r: r["violations"])),
        ("Right decisions", _pct(parts["decisions"]),
         change(parts["decisions"], lambda r: r["parts"]["decisions"], 100), True,
         series(lambda r: r["parts"]["decisions"])),
        ("Survives bad input", _pct(parts["robustness"]),
         change(parts["robustness"], lambda r: r["parts"]["robustness"], 100), True,
         series(lambda r: r["parts"]["robustness"])),
        ("Receipts verify", _pct(parts["receipts"]),
         change(parts["receipts"], lambda r: r["parts"]["receipts"], 100), True,
         series(lambda r: r["parts"]["receipts"])),
        ("Sabotage caught", f"{mutants['caught']}/{mutants['total']}",
         change(mutants["caught"], lambda r: r["mutants_caught"]), True,
         series(lambda r: r["mutants_caught"])),
        ("Speed, not scored", f"{result['speed_ms']} ms",
         change(result["speed_ms"], lambda r: r["speed_ms"]), False,
         series(lambda r: r["speed_ms"])),
    ]
    tile_w = (W - 2 * PAD - 5 * 12) / 6
    for i, (label, value, delta, higher_is_better, values) in enumerate(tiles):
        good = delta is not None and ((delta > 0) == higher_is_better)
        body.append(_tile(PAD + i * (tile_w + 12), 112, tile_w, label, value, delta, good, values))

    matrix, y = _matrix(result, 228)
    chart, y = _history(history, y + 18)
    body += [matrix, chart]
    height = y
    return (f'<svg xmlns="http://www.w3.org/2000/svg" class="card" viewBox="0 0 {W} {height}" '
            f'width="{W}" height="{height}" role="img" '
            f'aria-label="Actor bench: {result["verdict"]}, score {result["score"]} of 100, '
            f'{result["violations"]} safety violations">'
            f"<style>{STYLE}</style>"
            f'<rect width="{W}" height="{height}" rx="14" class="bg"/>{"".join(body)}</svg>')


PAGE_STYLE = """
:root{--page:#f6f5f1;--ink:#0b0b0b;--ink2:#52514e;--line:#e1e0d9;--good:#0ca30c;
--serious:#ec835a;--crit:#d03b3b;--muted:#898781}
@media (prefers-color-scheme: dark){:root{--page:#111110;--ink:#fff;--ink2:#c3c2b7;--line:#2c2c2a}}
body{margin:0;padding:24px 16px 48px;background:var(--page);color:var(--ink);
font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:920px;margin:0 auto}svg{max-width:100%;height:auto;display:block}
h2{font-size:15px;margin:28px 0 8px}table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:6px 10px 6px 0;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--ink2);font-weight:600}td.n{font-variant-numeric:tabular-nums;white-space:nowrap}
.b{display:inline-block;min-width:54px;white-space:nowrap}.b i{display:inline-block;width:9px;
height:9px;border-radius:2px;margin-right:6px}.pass i{background:var(--good)}
.fail i{background:var(--serious)}.crash i{background:var(--serious);border-radius:50%}
.unsafe i{background:var(--crit);transform:rotate(45deg)}
ul{margin:4px 0;padding-left:20px}details{margin-top:18px}summary{cursor:pointer;color:var(--ink2)}
code{font:12px ui-monospace,Consolas,monospace}.muted{color:var(--muted)}
.scroll{overflow-x:auto}
"""


def _badge(status: str) -> str:
    return f'<span class="b {status}"><i></i>{status}</span>'


def _counts(mapping: dict) -> str:
    return escape(", ".join(f"{k} {v}" for k, v in mapping.items())) or '<span class="muted">nothing</span>'


def _rows(scenarios: list) -> str:
    return "".join(
        f"<tr><td>{_badge(s['status'])}</td><td><code>{escape(s['id'])}</code><br>{escape(s['title'])}</td>"
        f"<td>{_counts(s['expected'])}</td><td>{_counts(s['executed'])}</td>"
        f"<td>{'<br>'.join(escape(p) for p in s['problems'][:4])}</td></tr>" for s in scenarios)


def html(result: dict, history: list) -> str:
    flipped = result["flipped"]
    changed = ""
    if flipped["fixed"] or flipped["broken"]:
        for label, ids in (("Fixed", flipped["fixed"]), ("Broken", flipped["broken"])):
            if ids:
                changed += f"<p><b>{label} ({len(ids)})</b></p><ul>" + "".join(
                    f"<li><code>{escape(i)}</code></li>" for i in ids) + "</ul>"
    else:
        changed = '<p class="muted">No scenario changed state since the last run.</p>'
    failing = [s for s in result["scenarios"] if s["status"] != "pass"]
    head = "<tr><th>State</th><th>Scenario</th><th>Must send</th><th>Sent</th><th>Problem</th></tr>"
    attention = (f'<div class="scroll"><table>{head}{_rows(failing)}</table></div>' if failing
                 else '<p class="muted">Every scenario passes.</p>')
    missed = result["mutants"]["missed"]
    sabotage = ("" if not missed else "<h2>Sabotage the range did not notice</h2><ul>"
                + "".join(f"<li>{escape(m)}</li>" for m in missed) + "</ul>")
    runs = "".join(
        f"<tr><td class='n'>{escape(r['ts'][11:16])}</td><td><code>{escape(r['commit'])}</code></td>"
        f"<td class='n'>{r['score']}</td><td class='n'>{r['violations']}</td>"
        f"<td class='n'>{r['scenario_count']}</td><td>{escape(r['verdict'])}</td></tr>"
        for r in reversed(history))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Actor bench</title><style>{PAGE_STYLE}</style></head><body><main>
{svg(result, history)}
<h2>Changed since the last run</h2>{changed}
<h2>Needs attention ({len(failing)})</h2>{attention}
{sabotage}
<details><summary>All {len(result['scenarios'])} scenarios</summary>
<div class="scroll"><table>{head}{_rows(result['scenarios'])}</table></div></details>
<details><summary>All {len(history)} runs</summary><div class="scroll"><table>
<tr><th>Time (UTC)</th><th>Commit</th><th>Score</th><th>Violations</th><th>Scenarios</th><th>Verdict</th></tr>
{runs}</table></div></details>
<p class="muted">Score = 40 right decisions + 20 survives bad input + 20 receipts verify + 10 lifecycle
+ 10 sabotage caught. Any safety violation makes the run UNSAFE whatever the score.</p>
</main></body></html>
"""


def write(result: dict, history: list) -> None:
    (HERE / "scorecard.svg").write_text(svg(result, history), encoding="utf-8")
    (HERE / "scorecard.html").write_text(html(result, history), encoding="utf-8")
