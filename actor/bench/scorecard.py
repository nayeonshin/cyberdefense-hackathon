"""Draw the bench result as an engineering drawing sheet.

scorecard.svg goes into the README, scorecard.html adds the nonconformance list.
The verdict is the release stamp, the run history is the revision table, the score
is one field of the title block and its make-up is the acceptance table.
"""
import base64
from html import escape
from pathlib import Path

HERE = Path(__file__).parent
W = 880
EDGE, FRAME = 8, 22            # trim line and drawing frame, as on an ISO 5457 sheet
LEFT, RIGHT = 36, W - 36       # inner margins of the drawing area

ACTIONS = ["feed", "urlscan", "netcraft", "abuseipdb", "notify_host", "notify_registrar",
           "mock_registrar", "confirm"]
GROUPS = [("act", "ACT"), ("withhold", "WITHHOLD"), ("hostile", "HOSTILE INPUT"),
          ("lifecycle", "LIFECYCLE"), ("pipeline", "PIPELINE")]
PARTS = [("decisions", "RIGHT DECISIONS", 40), ("robustness", "SURVIVES BAD INPUT", 20),
         ("receipts", "RECEIPTS VERIFY", 20), ("lifecycle", "LIFECYCLE", 10),
         ("mutants", "SABOTAGE CAUGHT", 10)]

PAPER, INK, SOFT, RULE = "#f2f4f1", "#16222e", "#4a5a68", "#b4bec4"
REDLINE, STAMP = "#c4281c", "#2536a8"


def _font_face() -> str:
    data = base64.b64encode((HERE / "assets" / "lettering.ttf").read_bytes()).decode("ascii")
    return ("@font-face{font-family:'Sheet';src:url(data:font/ttf;base64," + data
            + ") format('truetype')}")


def _style() -> str:
    return _font_face() + f"""
.sheet text{{font-family:'Sheet','Bahnschrift','DIN Alternate','Arial Narrow',sans-serif;fill:{INK}}}
.soft{{fill:{SOFT}!important}}.red{{fill:{REDLINE}!important}}.blue{{fill:{STAMP}!important}}
.l{{stroke:{INK};fill:none;stroke-width:.7}}.h{{stroke:{RULE};fill:none;stroke-width:.5}}
.f{{stroke:{INK};fill:none;stroke-width:1.6}}.t{{stroke:{INK};fill:none;stroke-width:1.1}}
.r{{stroke:{REDLINE};fill:none;stroke-width:1.2;stroke-linecap:round}}
.ink{{fill:{INK}}}.redfill{{fill:{REDLINE}}}
"""


def _t(x, y, content, size=10, cls="", anchor="start", spacing=0.4) -> str:
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" text-anchor="{anchor}" '
            f'letter-spacing="{spacing}" class="{cls}">{escape(str(content))}</text>')


def _line(x1, y1, x2, y2, cls="l") -> str:
    return f'<path d="M{x1:.1f} {y1:.1f}L{x2:.1f} {y2:.1f}" class="{cls}"/>'


def _clip(text: str, limit: int) -> str:
    """Cut at a word boundary so a note never ends mid-word."""
    return text if len(text) <= limit else text[:limit].rsplit(" ", 1)[0] + " ..."


def _rev(index: int) -> str:
    """Revision letters as on a drawing: A, B ... Z, AA."""
    out = ""
    index += 1
    while index:
        index, rem = divmod(index - 1, 26)
        out = chr(65 + rem) + out
    return out


def _frame(height: int) -> str:
    out = [f'<rect width="{W}" height="{height}" fill="{PAPER}"/>',
           f'<rect x="{EDGE}" y="{EDGE}" width="{W - 2 * EDGE}" height="{height - 2 * EDGE}" class="h"/>',
           f'<rect x="{FRAME}" y="{FRAME}" width="{W - 2 * FRAME}" height="{height - 2 * FRAME}" class="f"/>']
    cols, rows = 8, 4
    for i in range(cols):
        x0 = FRAME + (W - 2 * FRAME) * i / cols
        mid = x0 + (W - 2 * FRAME) / cols / 2
        if i:
            out += [_line(x0, EDGE, x0, FRAME, "h"), _line(x0, height - FRAME, x0, height - EDGE, "h")]
        out += [_t(mid, FRAME - 4, i + 1, 8, "soft", "middle"),
                _t(mid, height - EDGE - 4, i + 1, 8, "soft", "middle")]
    for j in range(rows):
        y0 = FRAME + (height - 2 * FRAME) * j / rows
        mid = y0 + (height - 2 * FRAME) / rows / 2 + 3
        if j:
            out += [_line(EDGE, y0, FRAME, y0, "h"), _line(W - FRAME, y0, W - EDGE, y0, "h")]
        out += [_t((EDGE + FRAME) / 2, mid, "ABCD"[j], 8, "soft", "middle"),
                _t(W - (EDGE + FRAME) / 2, mid, "ABCD"[j], 8, "soft", "middle")]
    return "".join(out)


def _mark(x, y, size, state) -> str:
    """Filled square: sent as required. Blank: held back. Hollow red: missing. Red cross: forbidden."""
    pad = 0.9
    if state == "acted":
        return (f'<rect x="{x + pad:.1f}" y="{y + pad:.1f}" width="{size - 2 * pad:.1f}" '
                f'height="{size - 2 * pad:.1f}" class="ink"/>')
    if state == "missed":
        return (f'<rect x="{x + 1:.1f}" y="{y + 1:.1f}" width="{size - 2:.1f}" '
                f'height="{size - 2:.1f}" class="r"/>')
    if state == "forbidden":
        return (f'<path d="M{x:.1f} {y:.1f}l{size:.1f} {size:.1f}M{x + size:.1f} {y:.1f}'
                f'l{-size:.1f} {size:.1f}" class="r"/>')
    return ""


def _arrow(x, y, direction) -> str:
    return f'<path d="M{x:.1f} {y:.1f}l{5 * direction} -1.7v3.4z" class="ink"/>'


def _view(result: dict, top: int) -> tuple:
    scenarios = []
    for key, _ in GROUPS:
        scenarios += [s for s in result["scenarios"] if s["group"] == key]
    x0, gap, row_h = LEFT + 112, 9, 12
    present = [g for g in GROUPS if any(s["group"] == g[0] for s in scenarios)]
    pitch = (RIGHT - x0 - gap * (len(present) - 1)) / max(1, len(scenarios))
    cell = min(pitch, row_h) - 0.6
    grid_top, grid_bottom = top + 44, top + 44 + row_h * len(ACTIONS)

    out = [_t(LEFT, top + 4, "VIEW A", 13, spacing=1),
           _line(LEFT, top + 8, LEFT + 46, top + 8, "t"),
           _t(LEFT + 58, top + 4, f"{len(scenarios)} SCENARIOS × {len(ACTIONS)} ACTIONS, "
              "EVERY CHANNEL RECORDED", 10, "soft")]

    # key to the marks, right-aligned on the view line
    kx = RIGHT - 408
    for state, words in (("acted", "SENT AS REQUIRED"), ("withheld", "BLANK: HELD BACK"),
                         ("missed", "MISSING"), ("forbidden", "FORBIDDEN")):
        if state != "withheld":
            out.append(_mark(kx, top - 4, 8, state))
            kx += 12
        out.append(_t(kx, top + 4, words, 10, "soft"))
        kx += len(words) * 6.1 + 14

    for row, action in enumerate(ACTIONS):
        y = grid_top + row * row_h
        out.append(_t(x0 - 8, y + row_h - 3, action.replace("_", " ").upper(), 10, "soft", "end"))

    x, columns, flagged = x0, {}, []
    for key, label in present:
        members = [s for s in scenarios if s["group"] == key]
        width = pitch * len(members)
        passed = sum(s["status"] == "pass" for s in members)
        cls = "" if passed == len(members) else "red"
        # dimension line with extension lines, the way a drawing states a length
        out += [_line(x, grid_top - 22, x, grid_top - 2), _line(x + width, grid_top - 22, x + width, grid_top - 2),
                _line(x, grid_top - 16, x + width, grid_top - 16),
                _arrow(x, grid_top - 16, 1), _arrow(x + width, grid_top - 16, -1),
                _t(x + width / 2, grid_top - 20, f"{label} {passed}/{len(members)}", 10, cls, "middle")]
        out.append(f'<rect x="{x:.1f}" y="{grid_top}" width="{width:.1f}" height="{row_h * len(ACTIONS)}" class="t"/>')
        for row in range(1, len(ACTIONS)):
            out.append(_line(x, grid_top + row * row_h, x + width, grid_top + row * row_h, "h"))
        for s in members:
            columns[s["id"]] = x
            for row, action in enumerate(ACTIONS):
                state = s["cells"].get(action, "withheld")
                tip = (f"{s['id']} / {action}: required {s['expected'].get(action, 0)}, "
                       f"sent {s['executed'].get(action, 0)}")
                mark = _mark(x + (pitch - cell) / 2, grid_top + row * row_h + (row_h - cell) / 2, cell, state)
                hit = (f'<rect x="{x:.1f}" y="{grid_top + row * row_h}" width="{pitch:.1f}" '
                       f'height="{row_h}" fill="none" pointer-events="all"/>')
                out.append(f"<g><title>{escape(tip)}</title>{hit}{mark}</g>")
            if s["status"] != "pass":
                flagged.append(s)
            x += pitch
        x += gap

    # redline every failing column and tie the first few to numbered notes
    notes = flagged[:5]
    for s in flagged:
        out.append(f'<rect x="{columns[s["id"]] - 0.5:.1f}" y="{grid_top - 2}" width="{pitch + 1:.1f}" '
                   f'height="{row_h * len(ACTIONS) + 4}" rx="1.5" class="r"/>')
    for n, s in enumerate(notes, start=1):
        cx = columns[s["id"]] + pitch / 2
        bx = min(max(x0 + 14 + (n - 1) * 22, cx - 60), cx + 60)
        out += [_line(cx, grid_bottom + 2, bx, grid_bottom + 13, "r"),
                f'<circle cx="{bx:.1f}" cy="{grid_bottom + 20}" r="7" class="r"/>',
                _t(bx, grid_bottom + 23.5, n, 9, "red", "middle", 0)]
    return "".join(out), grid_bottom + (34 if notes else 14), notes, len(flagged)


def _table(x, y, widths, header, rows, row_h=17, aligns=None) -> tuple:
    """A ruled table. rows hold (text, css class) cells. Returns (svg, bottom y)."""
    total = sum(widths)
    aligns = aligns or ["start"] * len(widths)
    height = row_h * (len(rows) + 1)
    out = [f'<rect x="{x}" y="{y}" width="{total}" height="{height}" class="t"/>',
           _line(x, y + row_h, x + total, y + row_h, "l")]
    cx = x
    for i, width in enumerate(widths):
        if i:
            out.append(_line(cx, y, cx, y + height, "h"))
        tx = cx + 6 if aligns[i] == "start" else cx + width - 6
        out.append(_t(tx, y + row_h - 5, header[i], 9, "soft", aligns[i], 0.6))
        for r, row in enumerate(rows):
            text, cls = row[i] if isinstance(row[i], tuple) else (row[i], "")
            out.append(_t(tx, y + row_h * (r + 2) - 5, text, 10, cls, aligns[i]))
        cx += width
    for r in range(1, len(rows)):
        out.append(_line(x, y + row_h * (r + 1), x + total, y + row_h * (r + 1), "h"))
    return "".join(out), y + height


def _acceptance(result: dict, x: int, y: int) -> tuple:
    parts, mutants = result["parts"], result["mutants"]
    rows = []
    for i, (key, label, weight) in enumerate(PARTS, start=1):
        value = parts[key]
        measured = f"{mutants['caught']}/{mutants['total']}" if key == "mutants" else f"{value * 100:.0f}%"
        cls = "" if value >= 0.9995 else "red"
        rows.append((str(i), label, str(weight), (measured, cls), (f"{weight * value:.1f}", cls)))
    rows.append(("", "SCORE", "100", "", (f"{result['score']:.1f}", "")))
    out = [_t(x, y - 6, "ACCEPTANCE", 11, spacing=1)]
    table, bottom = _table(x, y, [30, 156, 56, 72, 62], ["ITEM", "CHARACTERISTIC", "WEIGHT", "MEASURED", "POINTS"],
                           rows, aligns=["start", "start", "end", "end", "end"])
    out.append(table)
    width = 376
    out.append(_line(x, bottom - 17, x + width, bottom - 17, "t"))
    violations = result["violations"]
    gate = "MUST BE 0: NOT RELEASABLE" if violations else "MUST BE 0"
    out += [f'<rect x="{x}" y="{bottom + 6}" width="{width}" height="34" class="t"/>',
            _line(x, bottom + 23, x + width, bottom + 23, "h"),
            _t(x + 6, bottom + 18, "SAFETY VIOLATIONS", 10),
            _t(x + width - 6, bottom + 18, f"{violations}   {gate}", 10, "red" if violations else "", "end"),
            _t(x + 6, bottom + 35, "SPEED PER VERDICT, NOT SCORED", 10, "soft"),
            _t(x + width - 6, bottom + 35, f"{result['speed_ms']} ms", 10, "soft", "end")]
    return "".join(out), bottom + 40


def _notes(x: int, y: int, flagged: list, total_failing: int) -> tuple:
    lines = [("1. EVERY OUTSIDE CHANNEL IS REPLACED BY A RECORDER.", "soft"),
             ("2. ONE SAFETY VIOLATION MAKES THE RUN UNSAFE, WHATEVER THE SCORE.", "soft"),
             ("3. SCENARIOS ARE ONLY ADDED, NEVER REMOVED.", "soft")]
    out = [_t(x, y, "NOTES", 11, spacing=1)]
    for i, (text, cls) in enumerate(lines):
        out.append(_t(x, y + 16 + i * 14, text, 10, cls))
    y += 16 + len(lines) * 14 + 4
    for n, s in enumerate(flagged, start=1):
        problem = (s["problems"][0] if s["problems"] else s["status"]).upper()
        out += [f'<circle cx="{x + 6}" cy="{y - 3.5}" r="6" class="r"/>',
                _t(x + 6, y, n, 8, "red", "middle", 0),
                _t(x + 18, y, _clip(f"{s['id'].upper()}: {problem}", 58), 10, "red")]
        y += 15
    if total_failing > len(flagged):
        out.append(_t(x + 18, y, f"AND {total_failing - len(flagged)} MORE, SEE SHEET 2", 10, "red"))
        y += 14
    return "".join(out), y


def _revisions(history: list, x: int, y: int) -> tuple:
    runs = list(enumerate(history))[-6:][::-1]
    rows = []
    for index, run in runs:
        cls = "" if index == len(history) - 1 else "soft"
        rows.append(((_rev(index), cls), (run["ts"][11:16], cls), (run["commit"], cls),
                     (str(run["scenario_count"]), cls),
                     (str(run["violations"]), "red" if run["violations"] else cls),
                     (f"{run['score']:.1f}", cls), (run["verdict"], "red" if run["violations"] else cls)))
    out = [_t(x, y - 6, "REVISIONS", 11, spacing=1)]
    table, bottom = _table(x, y, [34, 46, 78, 46, 42, 50, 88],
                           ["REV", "UTC", "COMMIT", "SCEN.", "VIOL.", "SCORE", "STATE"], rows,
                           aligns=["start", "start", "start", "end", "end", "end", "start"])
    return "".join(out) + table, bottom


def _title_block(result: dict, history: list, x: int, y: int) -> str:
    width, h1, h2 = 384, 50, 30
    out = [f'<rect x="{x}" y="{y}" width="{width}" height="{h1 + 2 * h2}" class="f"/>',
           _line(x, y + h1, x + width, y + h1, "l"), _line(x, y + h1 + h2, x + width, y + h1 + h2, "l"),
           _line(x + 262, y, x + 262, y + h1, "l"),
           _t(x + 6, y + 11, "TITLE", 8, "soft", spacing=0.8),
           _t(x + 6, y + 31, "ACTOR BENCH", 19, spacing=1.2),
           _t(x + 6, y + 44, "ACTION LADDER UNDER TEST", 10, "soft"),
           _t(x + 268, y + 11, "SCORE", 8, "soft", spacing=0.8),
           _t(x + width - 34, y + 40, f"{result['score']:.1f}", 30, anchor="end", spacing=0),
           _t(x + width - 6, y + 40, "/100", 10, "soft", "end")]

    def cells(top, specs):
        cx, parts = x, []
        for i, (label, value, w, cls) in enumerate(specs):
            if i:
                parts.append(_line(cx, top, cx, top + h2, "h"))
            parts += [_t(cx + 6, top + 10, label, 8, "soft", spacing=0.8),
                      _t(cx + 6, top + 24, value, 11, cls)]
            cx += w
        return parts

    out += cells(y + h1, [("DWG NO.", f"AB-{result['scenario_hash'].upper()}", 110, ""),
                          ("REV", _rev(len(history) - 1), 70, ""), ("SHEET", "1 OF 2", 72, ""),
                          ("SCALE", "1 CELL = 1 CHECK", 132, "")])
    out += cells(y + h1 + h2, [("COMMIT", result["commit"], 110, ""),
                               ("SCENARIOS", str(result["scenario_count"]), 70, ""),
                               ("VIOLATIONS", str(result["violations"]), 72,
                                "red" if result["violations"] else ""),
                               ("DATE UTC", result["ts"][:16].replace("T", " "), 132, "")])
    return "".join(out)


def _stamp(result: dict, history: list, cx: float, cy: float) -> str:
    """The verdict as an inspection stamp: blue ink when releasable, red when not."""
    bad = result["verdict"] in ("UNSAFE", "REGRESSED")
    colour = REDLINE if bad else STAMP
    if result["violations"]:
        n = result["violations"]
        sub = f"{n} VIOLATION{'S' if n != 1 else ''}, NOT FOR RELEASE"
    elif result["delta"] is None:
        sub = "FIRST MEASUREMENT"
    elif result["verdict"] == "SAME":
        sub = f"NO CHANGE AT {result['score']:.1f}"
    else:
        sub = f"{result['previous_score']:.1f} TO {result['score']:.1f}"
    width, height = 214, 68
    x, y = cx - width / 2, cy - height / 2
    cls = "red" if bad else "blue"
    return (f'<g transform="rotate(-5 {cx:.1f} {cy:.1f})" opacity="0.92">'
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{width}" height="{height}" fill="none" '
            f'stroke="{colour}" stroke-width="2.4"/>'
            f'<rect x="{x + 4:.1f}" y="{y + 4:.1f}" width="{width - 8}" height="{height - 8}" fill="none" '
            f'stroke="{colour}" stroke-width="0.8"/>'
            + _t(cx, y + 17, f"BENCH VERDICT  REV {_rev(len(history) - 1)}", 9, cls, "middle", 1.2)
            + _t(cx, y + 44, result["verdict"], 27, cls, "middle", 3)
            + _t(cx, y + 58, sub, 9, cls, "middle", 0.8) + "</g>")


def svg(result: dict, history: list) -> str:
    view, y, flagged, total_failing = _view(result, 48)
    lower = y + 22
    acceptance, left_bottom = _acceptance(result, LEFT, lower)
    notes, left_bottom = _notes(LEFT, left_bottom + 24, flagged, total_failing)
    right_x = RIGHT - 384
    revisions, rev_bottom = _revisions(history, right_x, lower)
    block_h = 110
    height = int(max(left_bottom + 14, rev_bottom + 96 + block_h) + FRAME + 6)
    block_y = height - FRAME - 6 - block_h
    stamp = _stamp(result, history, right_x + 192, (rev_bottom + block_y) / 2)
    label = (f"Actor bench drawing sheet: {result['verdict']}, score {result['score']} of 100, "
             f"{result['violations']} safety violations, {result['scenario_count']} scenarios")
    return (f'<svg xmlns="http://www.w3.org/2000/svg" class="sheet" viewBox="0 0 {W} {height}" '
            f'width="{W}" height="{height}" role="img" aria-label="{escape(label)}">'
            f"<style>{_style()}</style>{_frame(height)}{view}{acceptance}{notes}{revisions}"
            f"{_title_block(result, history, right_x, block_y)}{stamp}</svg>")


def _page_style() -> str:
    return _font_face() + f"""
:root{{--desk:#c9cfca;--paper:{PAPER};--ink:{INK};--soft:{SOFT};--rule:{RULE};--red:{REDLINE};--blue:{STAMP}}}
@media (prefers-color-scheme: dark){{:root{{--desk:#1c2126}}}}
*{{box-sizing:border-box}}
html{{scrollbar-color:var(--soft) var(--desk)}}
body{{margin:0;padding:28px 16px 56px;background:var(--desk);color:var(--ink);
font:14px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,sans-serif}}
::selection{{background:var(--blue);color:var(--paper)}}
main{{max-width:{W}px;margin:0 auto}}
.sheet-wrap,section{{background:var(--paper);box-shadow:0 1px 2px #0003,0 10px 28px -12px #0006}}
svg{{display:block;width:100%;height:auto}}
section{{margin-top:22px;padding:22px 28px 26px;border:1.6px solid var(--ink);outline:1px solid var(--rule);
outline-offset:6px}}
h2{{font:400 15px/1.2 'Sheet',"Arial Narrow",sans-serif;letter-spacing:.08em;text-transform:uppercase;
margin:30px 0 10px}}
section>h2:first-child{{margin-top:0}}
h2 small{{font-size:11px;color:var(--soft);letter-spacing:.06em;margin-left:10px}}
table{{border-collapse:collapse;width:100%;font-size:13px;font-variant-numeric:tabular-nums}}
th{{font:400 11px 'Sheet',"Arial Narrow",sans-serif;letter-spacing:.09em;text-transform:uppercase;
color:var(--soft);text-align:left;padding:6px 12px 6px 2px;border-bottom:1.1px solid var(--ink)}}
td{{padding:7px 12px 7px 2px;border-bottom:.5px solid var(--rule);vertical-align:top}}
td.id{{font:400 12px 'Sheet',"Arial Narrow",sans-serif;letter-spacing:.04em;text-transform:uppercase;
white-space:nowrap}}
td.n{{white-space:nowrap}}
.state{{font:400 12px 'Sheet',"Arial Narrow",sans-serif;letter-spacing:.07em;text-transform:uppercase;
white-space:nowrap}}
.state svg{{display:inline;width:10px;height:10px;margin-right:6px;vertical-align:-1px}}
.bad{{color:var(--red)}}.muted{{color:var(--soft)}}
ul{{margin:4px 0 0;padding:0;list-style:none;columns:2;column-gap:28px}}
li{{font:400 12px 'Sheet',"Arial Narrow",sans-serif;letter-spacing:.04em;text-transform:uppercase;
padding:3px 0;border-bottom:.5px solid var(--rule);break-inside:avoid}}
details{{margin-top:18px}}
summary{{font:400 12px 'Sheet',"Arial Narrow",sans-serif;letter-spacing:.08em;text-transform:uppercase;
cursor:pointer;padding:8px 0;border-top:1.1px solid var(--ink);border-bottom:.5px solid var(--rule);
list-style-position:inside}}
summary:hover{{color:var(--blue)}}
:focus-visible{{outline:2px solid var(--blue);outline-offset:2px}}
.scroll{{overflow-x:auto}}
p{{margin:8px 0 0;max-width:70ch}}
@media (max-width:560px){{section{{padding:16px 14px 20px}}ul{{columns:1}}}}
"""


def _state(status: str) -> str:
    mark = _mark(0, 0, 10, {"pass": "acted", "fail": "missed"}.get(status, "forbidden"))
    icon = f'<svg viewBox="0 0 10 10" aria-hidden="true">{mark}</svg>'
    return f'<span class="state{"" if status == "pass" else " bad"}">{icon}{escape(status)}</span>'


def _counts(mapping: dict) -> str:
    text = ", ".join(f"{k.replace('_', ' ')} {v}" for k, v in mapping.items())
    return escape(text) or '<span class="muted">nothing</span>'


def _rows(scenarios: list) -> str:
    return "".join(
        f"<tr><td>{_state(s['status'])}</td><td class='id'>{escape(s['id'])}</td>"
        f"<td>{escape(s['title'])}</td><td>{_counts(s['expected'])}</td><td>{_counts(s['executed'])}</td>"
        f"<td class='{'bad' if s['problems'] else ''}'>{'<br>'.join(escape(p) for p in s['problems'][:4])}</td></tr>"
        for s in scenarios)


def html(result: dict, history: list) -> str:
    flipped = result["flipped"]
    changed = ""
    for label, ids, cls in (("Fixed", flipped["fixed"], ""), ("Broken", flipped["broken"], "bad")):
        if ids:
            changed += (f'<h2 class="{cls}">{label}<small>{len(ids)} since the last revision</small></h2><ul>'
                        + "".join(f"<li>{escape(i)}</li>" for i in ids) + "</ul>")
    if not changed:
        changed = ('<h2>Changes<small>since the last revision</small></h2>'
                   '<p class="muted">No scenario changed state.</p>')
    failing = [s for s in result["scenarios"] if s["status"] != "pass"]
    head = ("<tr><th>State</th><th>Scenario</th><th>What it checks</th><th>Must send</th>"
            "<th>Sent</th><th>Finding</th></tr>")
    if failing:
        attention = f'<div class="scroll"><table>{head}{_rows(failing)}</table></div>'
    else:
        attention = f'<p class="muted">None. All {len(result["scenarios"])} scenarios conform.</p>'
    missed = result["mutants"]["missed"]
    sabotage = ("" if not missed else '<h2 class="bad">Sabotage the bench did not notice</h2><ul>'
                + "".join(f"<li>{escape(m)}</li>" for m in missed) + "</ul>")
    runs = "".join(
        f"<tr><td class='id'>{_rev(i)}</td><td class='n'>{escape(r['ts'][11:16])}</td>"
        f"<td class='id'>{escape(r['commit'])}</td><td class='n'>{r['scenario_count']}</td>"
        f"<td class='n{' bad' if r['violations'] else ''}'>{r['violations']}</td>"
        f"<td class='n'>{r['score']:.1f}</td><td class='id{' bad' if r['violations'] else ''}'>"
        f"{escape(r['verdict'])}</td></tr>" for i, r in reversed(list(enumerate(history))))
    marks = (f"<style>.state svg .ink{{fill:{INK}}}.state svg .r{{stroke:{REDLINE};fill:none;"
             f"stroke-width:1.4;stroke-linecap:round}}</style>")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Actor bench, revision {_rev(len(history) - 1)}</title><style>{_page_style()}</style>{marks}</head><body><main>
<div class="sheet-wrap">{svg(result, history)}</div>
<section>
<h2>Nonconformances<small>sheet 2 of 2, {len(failing)} open</small></h2>{attention}
{changed}
{sabotage}
<details><summary>All {len(result['scenarios'])} scenarios</summary>
<div class="scroll"><table>{head}{_rows(result['scenarios'])}</table></div></details>
<details><summary>All {len(history)} revisions</summary><div class="scroll"><table>
<tr><th>Rev</th><th>UTC</th><th>Commit</th><th>Scenarios</th><th>Violations</th><th>Score</th><th>State</th></tr>
{runs}</table></div></details>
</section>
</main></body></html>
"""


def write(result: dict, history: list) -> None:
    (HERE / "scorecard.svg").write_text(svg(result, history), encoding="utf-8")
    (HERE / "scorecard.html").write_text(html(result, history), encoding="utf-8")
