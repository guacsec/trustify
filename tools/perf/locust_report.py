#!/usr/bin/env python3
"""Build a self-contained HTML report from Locust CSV output.

Usage:
    locust -f locustfile.py --headless --csv=results --csv-full-history ...

    # one run
    python3 locust_report.py report results -o report.html [--baseline previous/results]
            [--title "Trustify load test"] [--target http://trustify:8080]

    # many runs: finds every *_stats.csv under the given dirs (one run per prefix)
    python3 locust_report.py index runs/ [more-runs/ ...] -o site/ [--last 100]
    # -> site/index.html (trends, regressions, run list) + site/reports/<run>.html

The run time comes from the history file, else a timestamp in the path
(e.g. runs/2026-09-22T02-56-10/results), else the file's mtime.

Reads <prefix>_stats.csv, <prefix>_stats_history.csv, <prefix>_failures.csv and
<prefix>_exceptions.csv (each may also be gzipped as .csv.gz). Only the standard
library is used; the output HTML has no external dependencies. Per-run charts are
downsampled to at most 400 points.

Layout follows the Goose report used by trustify-scale-test-runs: run overview,
load plan, per-endpoint request and response-time tables grouped by resource,
with "(+delta)" against an optional baseline run. On top of that it adds
time-series charts from the history file (per endpoint when the run used
--csv-full-history).
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import gzip
import hashlib
import html
import json
import re
import sys
from pathlib import Path

PCTS = ["50%", "66%", "75%", "80%", "90%", "95%", "98%", "99%", "100%"]
HIST_PCTS = ["50%", "95%", "99%"]

# Order in which resource groups are shown; anything else goes to "other".
GROUPS = [
    "sbom", "advisory", "vulnerability", "purl", "license", "analysis",
    "recommendations", "importer", "group", "labels", "other",
]


# ---------------------------------------------------------------- loading

def num(v):
    if v is None:
        return None
    v = v.strip()
    if v in ("", "N/A"):
        return None
    try:
        f = float(v)
    except ValueError:
        return None
    return int(f) if f.is_integer() else f


def csv_path(path: Path) -> Path | None:
    """The CSV itself, or its gzipped copy (<name>.csv.gz)."""
    if path.exists():
        return path
    gz = path.with_name(path.name + ".gz")
    return gz if gz.exists() else None


def read_csv(path: Path) -> list[dict]:
    real = csv_path(path)
    if real is None:
        return []
    opener = gzip.open if real.suffix == ".gz" else open
    with opener(real, "rt", newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def metadata_path(prefix: str) -> Path:
    return Path(prefix).parent / "metadata.json"


def read_metadata(prefix: str) -> dict:
    try:
        value = json.loads(metadata_path(prefix).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def load_run(prefix: str) -> dict:
    p = Path(prefix)
    stats = read_csv(Path(f"{p}_stats.csv"))
    if not stats:
        sys.exit(f"error: {p}_stats.csv not found or empty")
    return {
        "stats": stats,
        "history": read_csv(Path(f"{p}_stats_history.csv")),
        "failures": read_csv(Path(f"{p}_failures.csv")),
        "exceptions": read_csv(Path(f"{p}_exceptions.csv")),
        "metadata": read_metadata(prefix),
    }


def group_of(name: str) -> str:
    m = re.match(r"^/api/v\d+/([^/?]+)", name)
    key = m.group(1) if m else name.lower()
    for g in GROUPS:
        if g == "other":
            continue
        if g in key:
            # "sbom-labels" and "*_sbom_labels" read better under labels
            if g == "sbom" and "label" in key:
                return "labels"
            if g == "advisory" and "label" in key:
                return "labels"
            return g
    return "other"


def endpoint_rows(stats: list[dict]) -> tuple[list[dict], dict | None]:
    rows, agg = [], None
    for r in stats:
        row = {
            "method": r.get("Type", ""),
            "name": r["Name"],
            "requests": num(r["Request Count"]) or 0,
            "fails": num(r["Failure Count"]) or 0,
            "avg": num(r["Average Response Time"]),
            "min": num(r["Min Response Time"]),
            "max": num(r["Max Response Time"]),
            "median": num(r["Median Response Time"]),
            "size": num(r["Average Content Size"]),
            "rps": num(r["Requests/s"]) or 0,
            "fps": num(r["Failures/s"]) or 0,
            "pct": {k: num(r.get(k)) for k in PCTS},
        }
        if r["Name"] == "Aggregated":
            agg = row
        else:
            row["group"] = group_of(row["name"])
            rows.append(row)
    return rows, agg


def key(row: dict) -> str:
    return f"{row['method']} {row['name']}"


def metadata_link(metadata: dict, key: str, label: str) -> str:
    value = metadata.get(key)
    if not isinstance(value, str) or not value.startswith(("http://", "https://")):
        return ""
    return f'<a href="{esc(value)}">{esc(label)}</a>'


def metadata_block(metadata: dict) -> str:
    if not metadata:
        return ""

    items = []
    if metadata.get("kind"):
        items.append(f"Type <b>{esc(metadata['kind'])}</b>")
    if metadata.get("dataset"):
        items.append(f"Dataset <b>{esc(metadata['dataset'])}</b>")
    if metadata.get("scenario"):
        items.append(f"Scenario <b>{esc(metadata['scenario'])}</b>")
    if metadata.get("branch"):
        items.append(f"Branch <b>{esc(metadata['branch'])}</b>")
    if metadata.get("commit"):
        commit = metadata_link(metadata, "commit_url", str(metadata["commit"])[:12])
        items.append(f"Commit <b>{commit or esc(str(metadata['commit'])[:12])}</b>")
    if metadata.get("pr_url"):
        pr = metadata.get("pr")
        items.append(metadata_link(metadata, "pr_url", f"PR #{pr}" if pr else "Pull request"))
    if metadata.get("run_url"):
        items.append(metadata_link(metadata, "run_url", "Workflow run"))
    items = [item for item in items if item]
    return f'<p class="meta">{" · ".join(items)}</p>' if items else ""


def run_source(metadata: dict) -> str:
    pr = metadata.get("pr")
    if metadata.get("pr_url"):
        return metadata_link(metadata, "pr_url", f"PR #{pr}" if pr else "Pull request")
    return metadata_link(metadata, "run_url", "Workflow run")


# ---------------------------------------------------------------- history

def history_series(history: list[dict]) -> tuple[list[int], list[int], dict]:
    """Returns (timestamps, users, {endpoint_key: {metric: [values]}})."""
    ts = sorted({int(r["Timestamp"]) for r in history})
    index = {t: i for i, t in enumerate(ts)}
    users = [None] * len(ts)
    series: dict[str, dict] = {}
    for r in history:
        i = index[int(r["Timestamp"])]
        name = r["Name"]
        k = "Aggregated" if name == "Aggregated" else f"{r.get('Type', '')} {name}"
        s = series.setdefault(
            k, {m: [None] * len(ts) for m in ["rps", "fps", *HIST_PCTS]}
        )
        s["rps"][i] = num(r["Requests/s"])
        s["fps"][i] = num(r["Failures/s"])
        for p in HIST_PCTS:
            s[p][i] = num(r[p])
        if name == "Aggregated":
            users[i] = num(r["User Count"])
    return downsample(ts, users, series)


MAX_POINTS = 400


def downsample(ts, users, series, limit=MAX_POINTS):
    """Bucket long runs to at most `limit` points: rates are averaged, latency
    percentiles and user counts take the bucket maximum so spikes stay visible."""
    n = len(ts)
    if n <= limit:
        return ts, users, series
    step = -(-n // limit)
    buckets = [range(i, min(i + step, n)) for i in range(0, n, step)]

    def agg(vals, how):
        out = []
        for b in buckets:
            v = [vals[i] for i in b if vals[i] is not None]
            out.append(None if not v else max(v) if how == "max" else sum(v) / len(v))
        return out

    new_series = {
        k: {m: agg(v, "mean" if m in ("rps", "fps") else "max") for m, v in s.items()}
        for k, s in series.items()
    }
    return [ts[b[0]] for b in buckets], agg(users, "max"), new_series


def load_plan(ts: list[int], users: list) -> list[dict]:
    """Collapse the user-count curve into increasing/maintaining/decreasing phases."""
    phases = []
    prev = None
    for t, u in zip(ts, users):
        if u is None:
            continue
        if prev is None:
            prev = (t, u)
            continue
        kind = "Increasing" if u > prev[1] else "Decreasing" if u < prev[1] else "Maintaining"
        if phases and phases[-1]["kind"] == kind:
            phases[-1].update(end=t, to=u)
        else:
            phases.append({"kind": kind, "start": prev[0], "end": t, "from": prev[1], "to": u})
        prev = (t, u)
    return phases


# ---------------------------------------------------------------- formatting

def esc(s) -> str:
    return html.escape("" if s is None else str(s))


def fmt(v, digits=0) -> str:
    if v is None:
        return "–"
    if isinstance(v, float) and digits:
        return f"{v:,.{digits}f}"
    return f"{round(v):,}" if isinstance(v, (int, float)) else str(v)


def fmt_ms(v) -> str:
    if v is None:
        return "–"
    return f"{v:,.2f}" if v < 10 else f"{v:,.0f}" if v >= 100 else f"{v:,.1f}"


def fmt_dur(seconds: int) -> str:
    h, rem = divmod(int(seconds), 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m:02d}m {s:02d}s" if h else f"{m}m {s:02d}s"


def utc(t: int) -> str:
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def delta(cur, base, *, lower_is_better=True, pct=False, digits=0) -> str:
    """Goose-style "(+x)" delta, tinted by whether it's an improvement."""
    if cur is None or base is None:
        return ""
    d = cur - base
    if abs(d) < (0.5 if digits == 0 else 10 ** -digits / 2):
        return '<span class="d">(0)</span>'
    worse = d > 0 if lower_is_better else d < 0
    cls = "d worse" if worse else "d better"
    txt = f"{d:+,.{digits}f}" if digits else f"{round(d):+,}"
    if pct and base:
        txt += f", {d / base:+.0%}"
    return f'<span class="{cls}">({txt})</span>'


# ---------------------------------------------------------------- html parts

def kpi(label: str, value: str, sub: str = "") -> str:
    sub_html = f'<div class="kpi-sub">{sub}</div>' if sub else ""
    return (
        f'<div class="kpi"><div class="kpi-label">{esc(label)}</div>'
        f'<div class="kpi-value">{value}</div>{sub_html}</div>'
    )


def request_table(rows, base) -> str:
    head = (
        "<tr><th>Method</th><th class=l>Name</th><th># Requests</th><th># Fails</th>"
        "<th>Fail %</th><th>Average (ms)</th><th>Min (ms)</th><th>Max (ms)</th>"
        "<th>Avg size (B)</th><th>RPS</th><th>Failures/s</th></tr>"
    )
    body = []
    for g in GROUPS:
        members = [r for r in rows if r["group"] == g]
        if not members:
            continue
        body.append(f'<tr class="grp"><td colspan="11">{esc(g)} <span>{len(members)}</span></td></tr>')
        for r in sorted(members, key=lambda r: r["name"]):
            b = base.get(key(r)) if base else None
            fr = r["fails"] / r["requests"] if r["requests"] else 0
            bad = ' class="bad"' if fr > 0 else ""
            body.append(
                f"<tr{bad}><td>{esc(r['method'])}</td><td class=l>{esc(r['name'])}</td>"
                f"<td>{fmt(r['requests'])} {delta(r['requests'], b and b['requests'], lower_is_better=False)}</td>"
                f"<td>{fmt(r['fails'])} {delta(r['fails'], b and b['fails'])}</td>"
                f"<td>{fr:.0%}</td>"
                f"<td>{fmt_ms(r['avg'])} {delta(r['avg'], b and b['avg'], digits=1)}</td>"
                f"<td>{fmt_ms(r['min'])}</td><td>{fmt_ms(r['max'])}</td>"
                f"<td>{fmt(r['size'])}</td>"
                f"<td>{fmt(r['rps'], 2)} {delta(r['rps'], b and b['rps'], lower_is_better=False, digits=1)}</td>"
                f"<td>{fmt(r['fps'], 2)}</td></tr>"
            )
    return f'<table class="data sortable filterable"><thead>{head}</thead><tbody>{"".join(body)}</tbody></table>'


def pct_table(rows, base) -> str:
    cols = ["50%", "75%", "90%", "95%", "99%", "100%"]
    head = "<tr><th>Method</th><th class=l>Name</th>" + "".join(
        f"<th>{c.replace('%', '%ile')}</th>" for c in cols) + "</tr>"
    body = []
    for g in GROUPS:
        members = [r for r in rows if r["group"] == g]
        if not members:
            continue
        body.append(f'<tr class="grp"><td colspan="{2 + len(cols)}">{esc(g)} <span>{len(members)}</span></td></tr>')
        for r in sorted(members, key=lambda r: r["name"]):
            b = base.get(key(r)) if base else None
            cells = "".join(
                f"<td>{fmt(r['pct'][c])} {delta(r['pct'][c], b and b['pct'][c])}</td>" for c in cols
            )
            body.append(f"<tr><td>{esc(r['method'])}</td><td class=l>{esc(r['name'])}</td>{cells}</tr>")
    return f'<table class="data sortable filterable"><thead>{head}</thead><tbody>{"".join(body)}</tbody></table>'


def slowest_table(rows) -> str:
    top = sorted(rows, key=lambda r: r["pct"]["95%"] or 0, reverse=True)[:10]
    body = "".join(
        f"<tr><td>{i}</td><td>{esc(r['method'])}</td><td class=l>{esc(r['name'])}</td>"
        f"<td>{fmt(r['pct']['95%'])}</td><td>{fmt_ms(r['avg'])}</td><td>{fmt(r['requests'])}</td></tr>"
        for i, r in enumerate(top, 1)
    )
    return (
        '<table class="data"><thead><tr><th>#</th><th>Method</th><th class=l>Name</th>'
        "<th>95%ile (ms)</th><th>Average (ms)</th><th># Requests</th></tr></thead>"
        f"<tbody>{body}</tbody></table>"
    )


def failures_table(failures) -> str:
    if not failures:
        return '<p class="empty">No failures recorded.</p>'
    rows = sorted(failures, key=lambda f: num(f["Occurrences"]) or 0, reverse=True)
    body = "".join(
        f"<tr><td>{esc(f['Method'])}</td><td class=l>{esc(f['Name'])}</td>"
        f"<td class=l><code>{esc(f['Error'])}</code></td><td>{fmt(num(f['Occurrences']))}</td></tr>"
        for f in rows
    )
    return (
        '<table class="data"><thead><tr><th>Method</th><th class=l>Name</th>'
        f'<th class=l>Error</th><th>Occurrences</th></tr></thead><tbody>{body}</tbody></table>'
    )


def exceptions_table(exceptions) -> str:
    if not exceptions:
        return '<p class="empty">No exceptions raised in the locustfile.</p>'
    body = "".join(
        f"<tr><td>{fmt(num(e['Count']))}</td><td class=l>{esc(e['Message'])}</td>"
        f"<td class=l><details><summary>traceback</summary><pre>{esc(e['Traceback'])}</pre></details></td>"
        f"<td class=l>{esc(e['Nodes'])}</td></tr>"
        for e in exceptions
    )
    return (
        '<table class="data"><thead><tr><th>Count</th><th class=l>Message</th>'
        f'<th class=l>Traceback</th><th class=l>Nodes</th></tr></thead><tbody>{body}</tbody></table>'
    )


def plan_table(phases) -> str:
    if not phases:
        return '<p class="empty">No history file, so the load plan is unknown.</p>'
    body = "".join(
        f"<tr><td class=l>{p['kind']}</td><td class=l>{utc(p['start'])[11:19]}</td>"
        f"<td class=l>{utc(p['end'])[11:19]}</td><td>{fmt_dur(p['end'] - p['start'])}</td>"
        f"<td>{p['from']} → {p['to']}</td></tr>"
        for p in phases
    )
    return (
        '<table class="data narrow"><thead><tr><th class=l>Action</th><th class=l>Started</th>'
        f'<th class=l>Stopped</th><th>Elapsed</th><th>Users</th></tr></thead><tbody>{body}</tbody></table>'
    )


# ---------------------------------------------------------------- page

CSS = r"""
:root{
  color-scheme:light;
  --bg:#f6f6f4;--surface:#fcfcfb;--border:#e4e3df;--grid:#ecebe7;
  --text:#0b0b0b;--text-2:#52514e;--text-3:#7a7974;
  --s1:#2a78d6;--s2:#eb6834;--s3:#1baf7a;
  --good:#0a7d0a;--bad:#c23232;--bad-bg:#fbeeee;--grp:#f0efec;
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]){
    color-scheme:dark;
    --bg:#121211;--surface:#1a1a19;--border:#2e2e2b;--grid:#262624;
    --text:#ffffff;--text-2:#c3c2b7;--text-3:#8e8d85;
    --s1:#3987e5;--s2:#d95926;--s3:#199e70;
    --good:#3ec43e;--bad:#e66767;--bad-bg:#2a1b1b;--grp:#232321;
  }
}
:root[data-theme="dark"]{
  color-scheme:dark;
  --bg:#121211;--surface:#1a1a19;--border:#2e2e2b;--grid:#262624;
  --text:#ffffff;--text-2:#c3c2b7;--text-3:#8e8d85;
  --s1:#3987e5;--s2:#d95926;--s3:#199e70;
  --good:#3ec43e;--bad:#e66767;--bad-bg:#2a1b1b;--grp:#232321;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
  font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,"Red Hat Text",sans-serif}
main{max-width:1280px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:16px;margin:32px 0 10px}
.meta{color:var(--text-2);margin:0 0 20px}
.meta b{color:var(--text);font-weight:600}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(150px,100%),1fr));gap:12px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:12px 14px}
.kpi-label{color:var(--text-2);font-size:12px}
.kpi-value small{font-size:13px;font-weight:500;color:var(--text-2)}
.kpi-value{font-size:22px;font-weight:600;font-variant-numeric:tabular-nums;margin-top:2px}
.kpi-sub{color:var(--text-3);font-size:12px}
.kpi-value .worse,.kpi-value .better{font-size:13px;font-weight:500}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(380px,100%),1fr));gap:12px}
.chart h3{margin:0 0 2px;font-size:14px}
.chart .sub{color:var(--text-3);font-size:12px;margin-bottom:6px}
.chart svg{display:block;width:100%;height:220px;overflow:visible}
.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--text-2);margin-top:6px}
.legend i{display:inline-block;width:14px;height:2px;border-radius:1px;vertical-align:middle;margin-right:6px}
.filters{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:0 0 12px}
.filters label{color:var(--text-2);font-size:12px}
select,input[type=search]{font:inherit;color:var(--text);background:var(--surface);
  border:1px solid var(--border);border-radius:6px;padding:5px 8px;max-width:100%}
.note{color:var(--text-3);font-size:12px}
.scroll{overflow-x:auto;border:1px solid var(--border);border-radius:8px;background:var(--surface)}
table.data{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums;font-size:13px}
table.data.narrow{width:auto}
table.data th,table.data td{padding:5px 10px;text-align:right;white-space:nowrap;border-bottom:1px solid var(--grid)}
table.data th{position:sticky;top:0;background:var(--surface);color:var(--text-2);font-weight:600;font-size:12px}
table.sortable th{cursor:pointer;user-select:none}
table.sortable th[aria-sort]::after{content:" ▾";color:var(--text-3)}
table.sortable th[aria-sort=ascending]::after{content:" ▴"}
table.data .l{text-align:left}
table.data td.l{max-width:520px;overflow:hidden;text-overflow:ellipsis}
table.data tr.grp td{background:var(--grp);text-align:left;font-weight:600;text-transform:uppercase;
  letter-spacing:.04em;font-size:11px;color:var(--text-2)}
table.data tr.grp span{font-weight:400;color:var(--text-3)}
table.data tr.bad td:nth-child(4),table.data tr.bad td:nth-child(5){color:var(--bad);font-weight:600}
table.data tr:hover td{background:color-mix(in srgb,var(--grp) 60%,transparent)}
code{font-size:12px}
pre{white-space:pre-wrap;font-size:12px;max-width:700px}
.d{color:var(--text-3);font-size:11px}
.d.worse{color:var(--bad)}
.d.better{color:var(--good)}
.empty{color:var(--text-3)}
.tip{position:fixed;pointer-events:none;background:var(--surface);border:1px solid var(--border);
  border-radius:6px;padding:6px 8px;font-size:12px;box-shadow:0 4px 14px rgba(0,0,0,.12);
  font-variant-numeric:tabular-nums;display:none;z-index:10}
.tip b{font-weight:600}
.tip .row{display:flex;gap:10px;justify-content:space-between}
.tip i{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px}
footer{margin-top:40px;color:var(--text-3);font-size:12px}
"""

CHART_JS = r"""
const DATA = JSON.parse(document.getElementById('data').textContent);
const css = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const tip = document.querySelector('.tip');
const fmtT = t => new Date(t*1000).toISOString().slice(11,19);
const fmtD = t => new Date(t*1000).toISOString().slice(0,10);
const fmtDT = t => new Date(t*1000).toISOString().slice(0,16).replace('T',' ');
const fmtV = (v,u) => v==null ? '–' : (Math.abs(v)>=100 ? Math.round(v).toLocaleString() : Math.abs(v)>=1 ? (+v.toFixed(1)).toLocaleString() : (+v.toFixed(2)).toLocaleString()) + (u||'');

function niceMax(v){ if(!v||v<=0) return 1; const p=Math.pow(10,Math.floor(Math.log10(v))); for(const m of [1,2,2.5,5,10]) if(m*p>=v) return m*p; return 10*p; }

function lineChart(host, xs, series, unit, opt={}){
  const fx = opt.fmtX || fmtT, ftip = opt.fmtTip || (i => fmtT(xs[i])+' UTC');
  const svg = host.querySelector('svg');
  const W = svg.clientWidth || 600, H = 220, L = 52, R = 12, T = 10, B = 26;
  const iw = W-L-R, ih = H-T-B;
  let x0 = xs[0], x1 = xs[xs.length-1];
  if(x0===undefined){ svg.innerHTML=''; host.querySelector('.legend').innerHTML=''; return; }
  if(x1===x0){ x0-=3600; x1+=3600; }
  let ymax = 0; for(const s of series) for(const v of s.values) if(v!=null && v>ymax) ymax=v;
  ymax = niceMax(ymax*1.05);
  const X = t => L + (t-x0)/(x1-x0||1)*iw, Y = v => T + ih - v/ymax*ih;
  let g = '';
  for(let i=0;i<=4;i++){ const v=ymax*i/4, y=Y(v);
    g += `<line x1="${L}" x2="${W-R}" y1="${y}" y2="${y}" stroke="${css('--grid')}"/>`;
    g += `<text x="${L-6}" y="${y+4}" text-anchor="end" font-size="11" fill="${css('--text-3')}">${fmtV(v)}</text>`; }
  const ticks = Math.max(2, Math.min(6, Math.floor(iw/95)));
  for(let i=0;i<=ticks;i++){ const t=x0+(x1-x0)*i/ticks;
    g += `<text x="${X(t)}" y="${H-6}" text-anchor="${i==0?'start':i==ticks?'end':'middle'}" font-size="11" fill="${css('--text-3')}">${fx(t, x1-x0)}</text>`; }
  for(const s of series){
    let d='', pen=false;
    s.values.forEach((v,i)=>{ if(v==null){pen=false;return;} d += (pen?'L':'M')+X(xs[i]).toFixed(1)+','+Y(v).toFixed(1); pen=true; });
    g += `<path d="${d}" fill="none" stroke="${css(s.color)}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`;
    if(opt.points && xs.length <= 400) s.values.forEach((v,i)=>{ if(v!=null) g += `<circle cx="${X(xs[i]).toFixed(1)}" cy="${Y(v).toFixed(1)}" r="3" fill="${css(s.color)}"/>`; });
  }
  g += `<line class="xh" y1="${T}" y2="${T+ih}" stroke="${css('--text-3')}" stroke-dasharray="3 3" visibility="hidden"/>`;
  series.forEach((s,k)=>{ g += `<circle class="dot" data-k="${k}" r="4" fill="${css(s.color)}" stroke="${css('--surface')}" stroke-width="2" visibility="hidden"/>`; });
  g += `<rect x="${L}" y="${T}" width="${iw}" height="${ih}" fill="transparent"/>`;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.innerHTML = g;
  host.querySelector('.legend').innerHTML = series.length>1 ? series.map(s=>`<span><i style="background:${css(s.color)}"></i>${s.name}</span>`).join('') : '';
  const xh = svg.querySelector('.xh'), dots = svg.querySelectorAll('.dot');
  let hovered = -1;
  svg.style.cursor = opt.links ? 'pointer' : '';
  svg.onclick = () => { if(opt.links && hovered>=0 && opt.links[hovered]) location.href = opt.links[hovered]; };
  svg.onmousemove = e => {
    const r = svg.getBoundingClientRect(), px = (e.clientX-r.left)*(W/r.width);
    if(px<L||px>W-R){ svg.onmouseleave(); return; }
    const t = x0+(px-L)/iw*(x1-x0); let i=0, best=Infinity;
    xs.forEach((x,j)=>{ const d=Math.abs(x-t); if(d<best){best=d;i=j;} });
    hovered = i;
    xh.setAttribute('x1',X(xs[i])); xh.setAttribute('x2',X(xs[i])); xh.setAttribute('visibility','visible');
    let rows = '';
    series.forEach((s,k)=>{ const v=s.values[i]; const dot=dots[k];
      if(v==null){dot.setAttribute('visibility','hidden');}
      else{dot.setAttribute('cx',X(xs[i]));dot.setAttribute('cy',Y(v));dot.setAttribute('visibility','visible');}
      rows += `<div class="row"><span><i style="background:${css(s.color)}"></i>${s.name}</span><b>${fmtV(v,' '+unit)}</b></div>`; });
    tip.innerHTML = `<div style="color:${css('--text-3')}">${ftip(i)}</div>${rows}`;
    tip.style.display='block';
    const tx = e.clientX+14, tw = tip.offsetWidth;
    tip.style.left = (tx+tw>innerWidth ? e.clientX-tw-14 : tx)+'px'; tip.style.top = (e.clientY+14)+'px';
  };
  svg.onmouseleave = () => { hovered=-1; tip.style.display='none'; xh.setAttribute('visibility','hidden'); dots.forEach(d=>d.setAttribute('visibility','hidden')); };
}

// sortable tables: sorts rows inside each resource group
document.querySelectorAll('table.sortable').forEach(tbl=>{
  tbl.querySelectorAll('th').forEach((th,ci)=>th.addEventListener('click',()=>{
    const asc = th.getAttribute('aria-sort')!=='ascending';
    tbl.querySelectorAll('th').forEach(h=>h.removeAttribute('aria-sort'));
    th.setAttribute('aria-sort', asc?'ascending':'descending');
    const val = td => { const t=td.childNodes[0]?.textContent?.trim()??''; const n=parseFloat(t.replace(/[,%]/g,'')); return isNaN(n)?t.toLowerCase():n; };
    const body = tbl.tBodies[0]; let cur={h:null,rows:[]}; const blocks=[cur];
    [...body.rows].forEach(r=>{ if(r.classList.contains('grp')){cur={h:r,rows:[]};blocks.push(cur);} else cur.rows.push(r); });
    blocks.forEach(b=>{ b.rows.sort((a,c)=>{const x=val(a.cells[ci]),y=val(c.cells[ci]); return (x>y?1:x<y?-1:0)*(asc?1:-1);});
      if(b.h) body.appendChild(b.h); b.rows.forEach(r=>body.appendChild(r)); });
  }));
});

// name filter
const q = document.getElementById('q');
if(q) q.oninput = () => { const s=q.value.toLowerCase();
  document.querySelectorAll('table.filterable tbody tr:not(.grp)').forEach(r=>{ const c=r.querySelector('td.name')||r.cells[1]; r.style.display = c.textContent.toLowerCase().includes(s)?'':'none'; }); };
"""

REPORT_JS = r"""
function render(){
  if(!DATA.ts.length) return;
  const sel = document.getElementById('endpoint');
  const k = sel ? sel.value : 'Aggregated';
  const s = DATA.series[k] || DATA.series['Aggregated'];
  lineChart(document.getElementById('c-rps'), DATA.ts, [
    {name:'Requests/s', values:s.rps, color:'--s1'},
    {name:'Failures/s', values:s.fps, color:'--s2'}], 'req/s');
  lineChart(document.getElementById('c-lat'), DATA.ts, [
    {name:'50%ile', values:s['50%'], color:'--s1'},
    {name:'95%ile', values:s['95%'], color:'--s2'},
    {name:'99%ile', values:s['99%'], color:'--s3'}], 'ms');
  lineChart(document.getElementById('c-users'), DATA.ts, [
    {name:'Users', values:DATA.users, color:'--s1'}], 'users');
}
const sel = document.getElementById('endpoint');
if(sel) sel.onchange = render;
const charts = document.querySelector('.charts');
if(charts) new ResizeObserver(()=>render()).observe(charts);
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', render);

"""


def build_report(prefix, baseline=None, title=None, target=None,
                 baseline_label=None, back=None) -> str:
    run = load_run(prefix)
    rows, agg = endpoint_rows(run["stats"])
    base_rows, base_agg = ({}, None)
    if baseline:
        b = load_run(baseline)
        br, base_agg = endpoint_rows(b["stats"])
        base_rows = {key(r): r for r in br}

    ts, users, series = history_series(run["history"])
    phases = load_plan(ts, users)
    full_history = len(series) > 1

    start, end = (ts[0], ts[-1]) if ts else (None, None)
    duration = (end - start) if ts else None
    peak_users = max((u for u in users if u is not None), default=None)
    total = agg["requests"] if agg else sum(r["requests"] for r in rows)
    fails = agg["fails"] if agg else sum(r["fails"] for r in rows)
    fail_rate = fails / total if total else 0
    rps = agg["rps"] if agg else None
    p95 = agg["pct"]["95%"] if agg else None
    p99 = agg["pct"]["99%"] if agg else None

    def bd(field, sub=None, **kw):
        if not base_agg:
            return ""
        cur = agg[field] if sub is None else agg[field][sub]
        b = base_agg[field] if sub is None else base_agg[field][sub]
        return delta(cur, b, **kw)

    meta = []
    if target:
        meta.append(f"Target <b>{esc(target)}</b>")
    if start:
        meta.append(f"<b>{utc(start)}</b> → <b>{utc(end)[11:]}</b>")
    if peak_users is not None:
        meta.append(f"Users <b>{peak_users}</b>")
    if baseline:
        meta.append(f"Deltas vs <b>{esc(baseline_label or baseline)}</b>")

    kpis = "".join([
        kpi("Duration", fmt_dur(duration) if duration else "–"),
        kpi("Total requests", fmt(total) + " " + bd("requests", lower_is_better=False)),
        kpi("Failure rate", f"{fail_rate:.1%}", f"{fmt(fails)} failed requests"),
        kpi("Throughput", f"{fmt(rps, 1)} <small>req/s</small> " + bd("rps", lower_is_better=False, digits=1)),
        kpi("Latency 95%ile", f"{fmt(p95)} <small>ms</small> " + bd("pct", "95%")),
        kpi("Latency 99%ile", f"{fmt(p99)} <small>ms</small> " + bd("pct", "99%")),
        kpi("Endpoints", str(len(rows)), f"{sum(1 for r in rows if r['fails'])} with failures"),
    ])

    if full_history:
        opts = ['<option value="Aggregated">All endpoints (aggregated)</option>'] + [
            f'<option value="{esc(k)}">{esc(k)}</option>' for k in sorted(series) if k != "Aggregated"
        ]
        chart_filter = (
            '<div class="filters"><label for="endpoint">Endpoint</label>'
            f'<select id="endpoint">{"".join(opts)}</select></div>'
        )
    else:
        chart_filter = (
            '<p class="note">History has aggregated data only. Run Locust with '
            "<code>--csv-full-history</code> to get per-endpoint charts.</p>"
        )

    charts = "" if not ts else f"""
<h2>Over time</h2>
{chart_filter}
<div class="charts">
  <div class="card chart" id="c-rps"><h3>Throughput</h3><div class="sub">Requests and failures per second</div><svg role="img" aria-label="Throughput over time"></svg><div class="legend"></div></div>
  <div class="card chart" id="c-lat"><h3>Response time</h3><div class="sub">Percentiles over Locust's rolling window, ms</div><svg role="img" aria-label="Response time percentiles over time"></svg><div class="legend"></div></div>
  <div class="card chart" id="c-users"><h3>Users</h3><div class="sub">Concurrent simulated users</div><svg role="img" aria-label="Users over time"></svg><div class="legend"></div></div>
</div>"""

    data = {"ts": ts, "users": users, "series": series}
    data_json = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    title = title or "Locust load test report"
    back_html = f'<p class="back"><a href="{esc(back)}">← All runs</a></p>' if back else ""
    metadata_html = metadata_block(run["metadata"])

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title>
<style>{CSS}</style></head>
<body><main>
{back_html}
<h1>{esc(title)}</h1>
<p class="meta">{" · ".join(meta)}</p>
{metadata_html}
<div class="kpis">{kpis}</div>
{charts}
<h2>Load plan</h2>
<div class="scroll" style="display:inline-block;max-width:100%">{plan_table(phases)}</div>
<h2>Top 10 slowest endpoints (95%ile)</h2>
<div class="scroll">{slowest_table(rows)}</div>
<h2>Request metrics</h2>
<div class="filters"><label for="q">Filter</label><input id="q" type="search" placeholder="endpoint name…"></div>
<div class="scroll">{request_table(rows, base_rows)}</div>
<h2>Response time metrics (ms)</h2>
<div class="scroll">{pct_table(rows, base_rows)}</div>
<h2>Failures</h2>
<div class="scroll">{failures_table(run["failures"])}</div>
<h2>Exceptions</h2>
<div class="scroll">{exceptions_table(run["exceptions"])}</div>
<footer>Generated {dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")} from <code>{esc(Path(prefix).name)}_*.csv</code> by locust_report.py</footer>
</main>
<div class="tip"></div>
<script id="data" type="application/json">{data_json}</script>
<script>{CHART_JS}{REPORT_JS}</script>
</body></html>"""


# ================================================================ multi-run index

TS_IN_PATH = re.compile(r"(\d{4})-?(\d{2})-?(\d{2})[T_ -]?(\d{2})[-:.]?(\d{2})[-:.]?(\d{2})")


def discover_runs(paths: list[str]) -> list[dict]:
    """Find every <prefix>_stats.csv under the given dirs (or prefixes)."""
    found: dict[str, dict] = {}
    for raw in paths:
        root = Path(raw)
        if root.is_dir():
            candidates = [(c, root) for c in [*root.rglob("*_stats.csv"), *root.rglob("*_stats.csv.gz")]]
        else:  # a prefix like runs/2026-09-22/results
            c = csv_path(Path(f"{root}_stats.csv"))
            candidates = [(c, c.parent.parent)] if c else []
            if not candidates:
                print(f"warning: no runs found for {raw}", file=sys.stderr)
        for stats, base in candidates:
            prefix = re.sub(r"_stats\.csv(\.gz)?$", "", str(stats))
            if prefix in found:
                continue
            rel = Path(prefix).relative_to(base) if Path(prefix).is_relative_to(base) else Path(prefix)
            label = str(rel.parent) if str(rel.parent) not in ("", ".") else rel.name
            if rel.name not in ("results", "locust") and str(rel.parent) not in ("", "."):
                label = f"{rel.parent}/{rel.name}"
            found[prefix] = {"prefix": prefix, "label": label}
    return list(found.values())


def run_start(prefix: str, history: list[dict]) -> int:
    if history:
        return min(int(r["Timestamp"]) for r in history)
    m = TS_IN_PATH.search(prefix)
    if m:
        y, mo, d, h, mi, se = map(int, m.groups())
        try:
            return int(dt.datetime(y, mo, d, h, mi, se, tzinfo=dt.timezone.utc).timestamp())
        except ValueError:
            pass
    return int(csv_path(Path(f"{prefix}_stats.csv")).stat().st_mtime)


def summarise(run: dict) -> dict:
    data = load_run(run["prefix"])
    rows, agg = endpoint_rows(data["stats"])
    ts, users, _ = history_series(data["history"])
    start = run_start(run["prefix"], data["history"])
    total = agg["requests"] if agg else sum(r["requests"] for r in rows)
    fails = agg["fails"] if agg else sum(r["fails"] for r in rows)
    return {
        **run,
        "t": start,
        "duration": (ts[-1] - ts[0]) if ts else None,
        "users": max((u for u in users if u is not None), default=None),
        "requests": total,
        "fails": fails,
        "fail_rate": fails / total if total else 0,
        "rps": agg["rps"] if agg else None,
        "avg": agg["avg"] if agg else None,
        "p50": agg["pct"]["50%"] if agg else None,
        "p95": agg["pct"]["95%"] if agg else None,
        "p99": agg["pct"]["99%"] if agg else None,
        "metadata": data["metadata"],
        "rows": {key(r): r for r in rows},
    }


def slugify(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-") or "run"


def sparkline(values: list, width=120, height=24) -> str:
    pts = [(i, v) for i, v in enumerate(values) if v is not None]
    if len(pts) < 2:
        return ""
    lo = min(v for _, v in pts)
    hi = max(v for _, v in pts)
    span = hi - lo or 1
    n = len(values) - 1 or 1
    xy = [(2 + i / n * (width - 4), height - 3 - (v - lo) / span * (height - 6)) for i, v in pts]
    d = "M" + "L".join(f"{x:.1f},{y:.1f}" for x, y in xy)
    lx, ly = xy[-1]
    return (
        f'<svg class="spark" width="{width}" height="{height}" viewBox="0 0 {width} {height}" aria-hidden="true">'
        f'<path d="{d}" fill="none" stroke="var(--s1)" stroke-width="1.5" stroke-linejoin="round"/>'
        f'<circle cx="{lx:.1f}" cy="{ly:.1f}" r="2.5" fill="var(--s1)"/></svg>'
    )


def fail_pct(row) -> str:
    if not row:
        return "–"
    return f"{row['fails'] / row['requests']:.0%}" if row["requests"] else "0%"


def median(vals):
    v = sorted(x for x in vals if x is not None)
    if not v:
        return None
    m = len(v) // 2
    return v[m] if len(v) % 2 else (v[m - 1] + v[m]) / 2


INDEX_JS = r"""
const RANGES = {all: Infinity, '3m': 92*86400, '1m': 31*86400, '1w': 7*86400};
function visible(){
  const r = RANGES[document.getElementById('range').value];
  const last = DATA.runs.length ? DATA.runs[DATA.runs.length-1].t : 0;
  const idx = DATA.runs.map((x,i)=>i).filter(i => last - DATA.runs[i].t <= r);
  return idx.length ? idx : DATA.runs.map((x,i)=>i);
}
function renderIndex(){
  const idx = visible();
  const k = document.getElementById('endpoint').value;
  const xs = idx.map(i=>DATA.runs[i].t);
  const links = idx.map(i=>DATA.runs[i].href);
  const pick = f => idx.map(i => k==='Aggregated' ? DATA.runs[i][f] : (DATA.endpoints[k][i]||{})[f] ?? null);
  const span = xs.length ? xs[xs.length-1]-xs[0] : 0;
  const fx = t => span < 2*86400 ? fmtDT(t).slice(5) : fmtD(t);
  const opt = {fmtX: fx, points: true, links, fmtTip: j => `${fmtDT(xs[j])} UTC · ${DATA.runs[idx[j]].label}`};
  lineChart(document.getElementById('t-lat'), xs, [
    {name:'Average', values:pick('avg'), color:'--s1'},
    {name:'95%ile', values:pick('p95'), color:'--s2'},
    {name:'99%ile', values:pick('p99'), color:'--s3'}], 'ms', opt);
  lineChart(document.getElementById('t-rps'), xs, [
    {name:'Requests/s', values:pick('rps'), color:'--s1'}], 'req/s', opt);
  lineChart(document.getElementById('t-err'), xs, [
    {name:'Failure rate', values:pick('fail_rate').map(v=>v==null?null:v*100), color:'--s1'}], '%', opt);
  document.getElementById('range-note').textContent = `${idx.length} of ${DATA.runs.length} runs`;
}
['range','endpoint'].forEach(id => document.getElementById(id).onchange = renderIndex);
new ResizeObserver(()=>renderIndex()).observe(document.querySelector('.charts'));
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', renderIndex);
"""


def build_index(runs: list[dict], title: str, target: str | None, threshold_pct: float,
                threshold_ms: float) -> str:
    latest = runs[-1]
    prev = runs[-2] if len(runs) > 1 else None
    all_keys = sorted({k for r in runs for k in r["rows"]},
                      key=lambda k: (GROUPS.index(group_of(k.split(" ", 1)[-1])), k))

    endpoints = {
        k: [
            (lambda row: None if row is None else {
                "avg": row["avg"], "p95": row["pct"]["95%"], "p99": row["pct"]["99%"],
                "rps": row["rps"],
                "fail_rate": row["fails"] / row["requests"] if row["requests"] else 0,
            })(r["rows"].get(k))
            for r in runs
        ]
        for k in all_keys
    }
    data = {
        "runs": [{f: r[f] for f in ("t", "label", "href", "avg", "p95", "p99", "rps", "fail_rate")} for r in runs],
        "endpoints": endpoints,
    }

    def d(field, **kw):
        return delta(latest[field], prev and prev[field], **kw) if prev else ""

    kpis = "".join([
        kpi("Test runs", str(len(runs)), f"{fmt_date(runs[0]['t'])} → {fmt_date(latest['t'])}"),
        kpi("Latest avg response", f"{fmt_ms(latest['avg'])} <small>ms</small> " + d("avg", digits=1)),
        kpi("Latest 95%ile", f"{fmt(latest['p95'])} <small>ms</small> " + d("p95")),
        kpi("Latest throughput", f"{fmt(latest['rps'], 1)} <small>req/s</small> " + d("rps", lower_is_better=False, digits=1)),
        kpi("Latest failure rate", f"{latest['fail_rate']:.1%}",
            f"{fmt(latest['fails'])} of {fmt(latest['requests'])} requests"),
        kpi("Endpoints tested", str(len(latest["rows"])), f"{len(all_keys)} across all runs"),
    ])

    opts = ['<option value="Aggregated">All endpoints (aggregated)</option>'] + [
        f'<option value="{esc(k)}">{esc(k)}</option>' for k in all_keys
    ]

    # latest vs previous, per endpoint
    if prev:
        changes = []
        for k, row in latest["rows"].items():
            b = prev["rows"].get(k)
            if not b or row["pct"]["95%"] is None or b["pct"]["95%"] is None:
                continue
            dm = row["pct"]["95%"] - b["pct"]["95%"]
            dp = dm / b["pct"]["95%"] if b["pct"]["95%"] else 0
            changes.append((k, row, b, dm, dp))
        regress = [c for c in changes if c[3] >= threshold_ms and c[4] >= threshold_pct / 100]
        improve = [c for c in changes if -c[3] >= threshold_ms and -c[4] >= threshold_pct / 100]

        def change_rows(items):
            return "".join(
                f"<tr><td class='l name'>{esc(k)}</td><td>{fmt(b['pct']['95%'])}</td><td>{fmt(r['pct']['95%'])}</td>"
                f"<td>{delta(r['pct']['95%'], b['pct']['95%'])}</td><td>{dp:+.0%}</td>"
                f"<td>{fmt_ms(b['avg'])}</td><td>{fmt_ms(r['avg'])}</td>"
                f"<td>{fmt(b['fails'])} → {fmt(r['fails'])}</td></tr>"
                for k, r, b, dm, dp in items
            )
        head = ("<thead><tr><th class=l>Endpoint</th><th>Prev 95%ile</th><th>Latest 95%ile</th><th>Δ ms</th>"
                "<th>Δ %</th><th>Prev avg</th><th>Latest avg</th><th>Fails</th></tr></thead>")
        crit = f"95%ile up or down by at least {threshold_pct:g}% and {threshold_ms:g} ms"
        new_eps = sorted(set(latest["rows"]) - set(prev["rows"]))
        gone_eps = sorted(set(prev["rows"]) - set(latest["rows"]))
        extra = ""
        if new_eps or gone_eps:
            extra = '<p class="note">' + (
                f"New in latest: {', '.join(esc(x) for x in new_eps[:8])}{' …' if len(new_eps) > 8 else ''}. " if new_eps else ""
            ) + (
                f"Missing from latest: {', '.join(esc(x) for x in gone_eps[:8])}{' …' if len(gone_eps) > 8 else ''}." if gone_eps else ""
            ) + "</p>"
        changes_html = f"""
<h2>Latest run vs previous</h2>
<p class="note">Comparing <a href="{esc(latest['href'])}">{esc(latest['label'])}</a> with
<a href="{esc(prev['href'])}">{esc(prev['label'])}</a>. Flagged when {crit}.</p>
<h3 class="sub-h">Regressions <span class="count">{len(regress)}</span></h3>
{('<div class="scroll"><table class="data sortable">' + head + '<tbody>' + change_rows(sorted(regress, key=lambda c: -c[4])) + '</tbody></table></div>') if regress else '<p class="empty">None.</p>'}
<h3 class="sub-h">Improvements <span class="count">{len(improve)}</span></h3>
{('<div class="scroll"><table class="data sortable">' + head + '<tbody>' + change_rows(sorted(improve, key=lambda c: c[4])) + '</tbody></table></div>') if improve else '<p class="empty">None.</p>'}
{extra}"""
    else:
        changes_html = '<h2>Latest run vs previous</h2><p class="empty">Only one run, so there is nothing to compare yet.</p>'

    # all endpoints overview
    spark_n = 30
    ov = []
    for k in all_keys:
        series = [e and e["p95"] for e in endpoints[k]]
        seen = [v for v in series if v is not None]
        lr = latest["rows"].get(k)
        ov.append(
            f"<tr><td>{esc(group_of(k.split(' ', 1)[-1]))}</td><td class='l name'>{esc(k)}</td><td>{len(seen)}</td>"
            f"<td>{fmt(lr and lr['pct']['95%'])}</td><td>{fmt(median(seen))}</td>"
            f"<td>{fmt(min(seen) if seen else None)}</td><td>{fmt(max(seen) if seen else None)}</td>"
            f"<td>{fmt_ms(lr and lr['avg'])}</td>"
            f"<td>{fail_pct(lr)}</td>"
            f"<td class='l'>{sparkline(series[-spark_n:])}</td></tr>"
        )
    overview = (
        '<table class="data sortable filterable"><thead><tr><th>Group</th><th class=l>Endpoint</th><th>Runs</th>'
        "<th>Latest 95%ile</th><th>Median 95%ile</th><th>Best</th><th>Worst</th><th>Latest avg</th>"
        f"<th>Latest fail %</th><th class=l>95%ile, last {spark_n} runs</th></tr></thead><tbody>{''.join(ov)}</tbody></table>"
    )

    # runs list, newest first
    rl = []
    for i in range(len(runs) - 1, -1, -1):
        r, b = runs[i], runs[i - 1] if i else None
        source = run_source(r.get("metadata", {}))
        rl.append(
            f"<tr><td class='l'><a href=\"{esc(r['href'])}\">{fmt_dt(r['t'])}</a></td><td class='l name'>{esc(r['label'])}</td>"
            f"<td>{source}</td>"
            f"<td>{fmt_dur(r['duration']) if r['duration'] else '–'}</td><td>{fmt(r['users'])}</td>"
            f"<td>{fmt(r['requests'])}</td><td>{r['fail_rate']:.1%}</td>"
            f"<td>{fmt(r['rps'], 1)} {delta(r['rps'], b and b['rps'], lower_is_better=False, digits=1)}</td>"
            f"<td>{fmt_ms(r['avg'])} {delta(r['avg'], b and b['avg'], digits=1)}</td>"
            f"<td>{fmt(r['p95'])} {delta(r['p95'], b and b['p95'])}</td>"
            f"<td>{fmt(r['p99'])} {delta(r['p99'], b and b['p99'])}</td></tr>"
        )
    runs_table = (
        '<table class="data sortable filterable"><thead><tr><th class=l>Started (UTC)</th><th class=l>Run</th><th>Source</th>'
        "<th>Duration</th><th>Users</th><th># Requests</th><th>Fail %</th><th>RPS</th><th>Average (ms)</th>"
        f"<th>95%ile</th><th>99%ile</th></tr></thead><tbody>{''.join(rl)}</tbody></table>"
    )

    latest_rows = list(latest["rows"].values())
    for r in latest_rows:
        r.setdefault("group", group_of(r["name"]))

    meta = []
    if target:
        meta.append(f"Target <b>{esc(target)}</b>")
    meta.append(f"Latest run <a href=\"{esc(latest['href'])}\"><b>{fmt_dt(latest['t'])} UTC</b></a>")
    data_json = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title>
<style>{CSS}{INDEX_CSS}</style></head>
<body><main>
<h1>{esc(title)}</h1>
<p class="meta">{" · ".join(meta)}</p>
<div class="kpis">{kpis}</div>

<h2>Trends</h2>
<div class="filters">
  <label for="range">Time range</label>
  <select id="range"><option value="all">All time</option><option value="3m">Last 3 months</option>
  <option value="1m">Last month</option><option value="1w">Last week</option></select>
  <label for="endpoint">Endpoint</label>
  <select id="endpoint">{"".join(opts)}</select>
  <span class="note" id="range-note"></span>
</div>
<div class="charts">
  <div class="card chart" id="t-lat"><h3>Response time</h3><div class="sub">Per run, ms · click a point to open that run</div><svg role="img" aria-label="Response time per run"></svg><div class="legend"></div></div>
  <div class="card chart" id="t-rps"><h3>Throughput</h3><div class="sub">Requests per second, per run</div><svg role="img" aria-label="Throughput per run"></svg><div class="legend"></div></div>
  <div class="card chart" id="t-err"><h3>Failure rate</h3><div class="sub">Failed requests, % of all requests</div><svg role="img" aria-label="Failure rate per run"></svg><div class="legend"></div></div>
</div>
{changes_html}
<h2>Top 10 slowest endpoints (latest run)</h2>
<div class="scroll">{slowest_table(latest_rows)}</div>
<h2>All endpoints</h2>
<div class="filters"><label for="q">Filter</label><input id="q" type="search" placeholder="endpoint or run name…"></div>
<div class="scroll">{overview}</div>
<h2>Runs</h2>
<div class="scroll">{runs_table}</div>
<footer>Generated {dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")} from {len(runs)} Locust runs by locust_report.py</footer>
</main>
<div class="tip"></div>
<script id="data" type="application/json">{data_json}</script>
<script>{CHART_JS}{INDEX_JS}</script>
</body></html>"""


INDEX_CSS = r"""
a{color:var(--s1)}
.back{margin:0 0 8px;font-size:13px}
.sub-h{font-size:14px;margin:18px 0 8px}
.count{color:var(--text-3);font-weight:400}
.spark{display:block}
"""


def fmt_date(t: int) -> str:
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%d")


def fmt_dt(t: int) -> str:
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%d %H:%M")


CACHE_NAME = ".locust-report-cache.json"
SUFFIXES = ("stats", "stats_history", "failures", "exceptions")


def script_hash() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()[:16]


def source_sig(prefix: str) -> list:
    """Content hash of a run's CSVs. Not mtimes: a fresh git checkout resets those."""
    sig = []
    for sfx in SUFFIXES:
        f = csv_path(Path(f"{prefix}_{sfx}.csv"))
        sig.append([sfx, hashlib.sha256(f.read_bytes()).hexdigest()[:16] if f else None])
    metadata = metadata_path(prefix)
    sig.append(["metadata", hashlib.sha256(metadata.read_bytes()).hexdigest()[:16] if metadata.exists() else None])
    return sig


def load_cache(out: Path, version: str) -> dict:
    try:
        cache = json.loads((out / CACHE_NAME).read_text(encoding="utf-8"))
        if cache.get("version") == version:
            return cache
    except (OSError, ValueError):
        pass
    return {"version": version, "summaries": {}, "reports": {}}


def cmd_index(args):
    out = Path(args.output)
    (out / "reports").mkdir(parents=True, exist_ok=True)
    version = script_hash()
    cache = load_cache(out, version) if not args.force else {"version": version, "summaries": {}, "reports": {}}

    found = discover_runs(args.paths)
    if not found:
        sys.exit("error: no <prefix>_stats.csv files found")

    # summaries: only re-parse runs whose CSVs changed
    summaries, parsed = [], 0
    for r in found:
        sig = source_sig(r["prefix"])
        c = cache["summaries"].get(r["prefix"])
        if c and c["sig"] == sig:
            summ = {**c["summary"], "label": r["label"]}
        else:
            summ = summarise(r)
            parsed += 1
        cache["summaries"][r["prefix"]] = {"sig": sig, "summary": summ}
        summaries.append({**summ, "sig": sig})
    live = {r["prefix"] for r in found}
    cache["summaries"] = {k: v for k, v in cache["summaries"].items() if k in live}

    runs = sorted(summaries, key=lambda r: r["t"])
    if args.last:
        runs = runs[-args.last:]
    used = set()
    for r in runs:
        stamp = fmt_dt(r["t"]).replace(" ", "T").replace(":", "-")
        slug = slugify(r["label"] if TS_IN_PATH.search(r["label"]) else f"{stamp}_{r['label']}")
        while slug in used:
            slug += "_"
        used.add(slug)
        r["href"] = f"reports/{slug}.html"
    written = skipped = 0
    for i, r in enumerate(runs):
        prev = runs[i - 1] if i else None
        title = f"{args.title} · {fmt_dt(r['t'])} UTC"
        # a report depends on its own CSVs, its baseline's CSVs, the options and this script
        report_sig = hashlib.sha256(json.dumps(
            [version, r["prefix"], r["sig"], prev and prev["prefix"], prev and prev["sig"],
             prev and prev["label"], r.get("metadata"), title, args.target], default=str).encode()).hexdigest()
        path = out / r["href"]
        if args.index_only or (cache["reports"].get(r["href"]) == report_sig and path.exists()):
            skipped += 1
            continue
        page = build_report(
            r["prefix"],
            baseline=prev and prev["prefix"],
            baseline_label=prev and f"previous run ({fmt_dt(prev['t'])} UTC, {prev['label']})",
            title=title,
            target=args.target,
            back="../index.html",
        )
        path.write_text(page, encoding="utf-8")
        cache["reports"][r["href"]] = report_sig
        written += 1

    if args.prune:
        keep = {r["href"] for r in runs}
        for f in (out / "reports").glob("*.html"):
            rel = f"reports/{f.name}"
            if rel not in keep:
                f.unlink()
                cache["reports"].pop(rel, None)
                print(f"pruned {rel}")
    (out / "index.html").write_text(
        build_index(runs, args.title, args.target, args.regression_pct, args.regression_ms),
        encoding="utf-8",
    )
    (out / CACHE_NAME).write_text(json.dumps(cache, separators=(",", ":")), encoding="utf-8")
    print(f"{len(runs)} runs ({parsed} parsed, {len(found) - parsed} from cache); "
          + (f"reports skipped (--index-only)" if args.index_only
             else f"reports: {written} written, {skipped} up to date")
          + f"; wrote {out / 'index.html'}")


def cmd_report(args):
    Path(args.output).write_text(
        build_report(args.prefix, baseline=args.baseline, title=args.title, target=args.target),
        encoding="utf-8",
    )
    print(f"wrote {args.output}")


def main():
    argv = sys.argv[1:]
    if argv and argv[0] not in ("report", "index", "-h", "--help"):
        argv = ["report", *argv]  # backwards compatible: locust_report.py <prefix> ...

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    rp = sub.add_parser("report", help="one run -> one HTML report")
    rp.add_argument("prefix", help="the --csv prefix used for the Locust run (e.g. results)")
    rp.add_argument("-o", "--output", default="report.html")
    rp.add_argument("--baseline", help="--csv prefix of an earlier run, for (+delta) columns")
    rp.add_argument("--title")
    rp.add_argument("--target", help="host under test, shown in the header")
    rp.set_defaults(func=cmd_report)

    ip = sub.add_parser("index", help="many runs -> index.html dashboard + one report per run")
    ip.add_argument("paths", nargs="+",
                    help="directories searched recursively for *_stats.csv, and/or run prefixes")
    ip.add_argument("-o", "--output", default="site", help="output directory (default: site)")
    ip.add_argument("--title", default="Locust load test dashboard")
    ip.add_argument("--target", help="host under test, shown in the header")
    ip.add_argument("--last", type=int, help="only include the most recent N runs")
    ip.add_argument("--regression-pct", type=float, default=10,
                    help="flag endpoints whose 95%%ile moved at least this many percent (default 10)")
    ip.add_argument("--regression-ms", type=float, default=5,
                    help="...and at least this many ms (default 5)")
    ip.add_argument("--force", action="store_true",
                    help="ignore the cache: re-parse every run and rewrite every report")
    ip.add_argument("--index-only", action="store_true",
                    help="only rebuild index.html; don't write any run reports")
    ip.add_argument("--prune", action="store_true",
                    help="delete reports in <output>/reports that no longer match a run")
    ip.set_defaults(func=cmd_index)

    args = ap.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
