"""Report writers: HTML (self-contained), JSON, SARIF 2.1.0 and Markdown."""
from __future__ import annotations

import datetime as dt
import json
from collections import Counter, defaultdict
from html import escape as e
from pathlib import Path

from . import __version__
from .catalog import RULES, SEV_ORDER, SEV_WEIGHT


def _sev(f):
    return f.effective_severity


def _fp_locs(f):
    return set((f.analysis or {}).get("false_positive_locations") or [])


def _loc(ev):
    return f"{ev.location}:{ev.line}" if ev.line else ev.location


def files_view(result):
    """[(location, risk, [(finding, evidence)])] sorted by risk."""
    by = defaultdict(list)
    for f in result.findings:
        if f.verdict == "likely_false_positive":
            continue
        fps = _fp_locs(f)
        for ev in f.evidence:
            if _loc(ev) in fps or ev.location in fps or ev.location.startswith("("):
                continue
            by[ev.location].append((f, ev))
    rows = []
    for loc, items in by.items():
        risk = sum(SEV_WEIGHT[_sev(f)] or 0.3 for f, ev in items)
        third = all(ev.third_party for _f, ev in items)
        rows.append((loc, risk * (0.4 if third else 1), third, sorted(items, key=lambda x: (SEV_ORDER.index(_sev(x[0])), x[1].line))))
    rows.sort(key=lambda r: (-r[1], r[0]))
    return rows


def grade(score):
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D" if score >= 35 else "F"


# ------------------------------------------------------------------ JSON / SARIF / Markdown
def write_json(result, path: Path):
    d = result.to_dict()
    d["tool"] = {"name": "mobsec-rag", "version": __version__}
    d["files"] = [{"location": loc, "risk": round(r, 1), "third_party": tp,
                   "issues": [{"rule_id": f.rule_id, "title": f.title, "severity": _sev(f), "line": ev.line,
                               "snippet": ev.snippet, "fix": f.fix} for f, ev in items]}
                  for loc, r, tp, items in files_view(result)]
    path.write_text(json.dumps(d, indent=2, default=str))


def write_sarif(result, path: Path):
    level = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
    used = sorted({f.rule_id for f in result.findings})
    rules = [{"id": rid, "name": rid.replace("-", ""), "shortDescription": {"text": RULES[rid]["title"]},
              "help": {"text": RULES[rid]["fix"]},
              "properties": {"tags": [RULES[rid]["masvs"], RULES[rid]["cwe"], RULES[rid]["top10"]],
                             "security-severity": {"high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}[RULES[rid]["severity"]]}}
             for rid in used]
    results = []
    for f in result.findings:
        if f.verdict == "likely_false_positive":
            continue
        a = f.analysis or {}
        msg = f"{f.title}. {a.get('risk') or ''} Fix: {'; '.join(a.get('fix_steps') or [f.fix])}"
        for ev in f.evidence:
            loc = {"physicalLocation": {"artifactLocation": {"uri": ev.location}}}
            if ev.line:
                loc["physicalLocation"]["region"] = {"startLine": ev.line, "snippet": {"text": ev.snippet[:300]}}
            elif "(" in ev.location and "/" not in ev.location:
                loc = {"logicalLocations": [{"fullyQualifiedName": ev.location, "kind": "function"}]}
            results.append({"ruleId": f.rule_id, "level": level[_sev(f)], "message": {"text": msg[:2000]},
                            "locations": [loc], "properties": {"thirdParty": ev.third_party, "evidence": ev.snippet[:300]}})
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": "mobsec-rag", "version": __version__,
                                           "informationUri": "https://github.com/DeepakPal25/mobsec-rag", "rules": rules}},
                       "results": results}]}
    path.write_text(json.dumps(sarif, indent=2))


def write_markdown(result, path: Path):
    app = result.app
    c = Counter(_sev(f) for f in result.findings if f.verdict != "likely_false_positive")
    out = [f"# Mobile security report: {app.get('package') or app.get('bundle_id') or Path(result.target).name}", "",
           f"- Target: `{result.target}` ({result.kind})",
           f"- Security score: **{app.get('score')}/100 ({grade(app.get('score', 0))})**",
           f"- Findings: {c.get('high', 0)} high, {c.get('medium', 0)} medium, {c.get('low', 0)} low, {c.get('info', 0)} info",
           f"- Analysis: {app.get('analysis_mode')}", "", "## Summary", "", result.summary, ""]
    if result.notes:
        out += ["> " + n for n in result.notes] + [""]
    out += ["## Findings", "", "| Severity | Issue | MASVS | Locations |", "|---|---|---|---|"]
    for f in result.findings:
        out.append(f"| {_sev(f)} | {f.title} | {f.masvs} | {len(f.evidence)} |")
    out.append("")
    for f in result.findings:
        a = f.analysis or {}
        out += [f"### [{_sev(f).upper()}] {f.title}", f"`{f.rule_id}` · {f.masvs} · {f.top10} · {f.cwe}"
                + (f" · verdict: {a.get('verdict').replace('_', ' ')}" if a.get('source') == 'llm' else ""), ""]
        if a.get("risk"):
            out += [a["risk"], ""]
        if a.get("attack_scenario"):
            out += [f"**Attack scenario:** {a['attack_scenario']}", ""]
        out += ["**Where:**", ""] + [f"- `{_loc(ev)}`{' (third-party)' if ev.third_party else ''}: `{ev.snippet[:160]}`"
                                     for ev in f.evidence[:15]]
        if len(f.evidence) > 15:
            out.append(f"- ... {len(f.evidence) - 15} more")
        out += ["", "**How to fix:**", ""] + [f"{i}. {s}" for i, s in enumerate(a.get("fix_steps") or [f.fix], 1)]
        if a.get("fix_code"):
            out += ["", f"```{a.get('fix_language') or ''}", a["fix_code"], "```"]
        if a.get("how_to_verify"):
            out += ["", f"**Verify:** {a['how_to_verify']}"]
        refs = [g for g in f.guidance if g.get("url")]
        if refs:
            out += ["", "References: " + ", ".join(f"[{g['title'][:60]}]({g['url']})" for g in refs)]
        out.append("")
    if result.kind not in ("apk", "ipa"):
        out += ["## Files with issues", "", "| File | Risk | Issues |", "|---|---|---|"]
        for loc, risk, tp, items in files_view(result)[:100]:
            out.append(f"| `{loc}`{' (3rd party)' if tp else ''} | {risk:.0f} | " +
                       "; ".join(f"L{ev.line} {f.title}" for f, ev in items[:6]) + " |")
    path.write_text("\n".join(out))


# ------------------------------------------------------------------ HTML
CSS = """
:root{--bg:#f6f5f2;--fg:#1c1b19;--card:#fff;--muted:#6d6b65;--line:#e4e2dc;--code:#f2f1ec;--accent:#2f5bd3;
--high:#c4372c;--medium:#c27403;--low:#2f6fb5;--info:#75736c;--ok:#2f8a4c}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#121211;--fg:#ebeae6;--card:#1c1c1a;--muted:#9e9c95;
--line:#31302d;--code:#252523;--accent:#7ea2ff;--high:#f06b5f;--medium:#f0a63a;--low:#6ea6e8;--info:#9e9c95;--ok:#5cc27e}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:1080px;margin:0 auto;padding:28px 16px 80px}
h1{font-size:26px;margin:0 0 2px;letter-spacing:-.01em}h2{font-size:18px;margin:28px 0 10px}
.muted{color:var(--muted)}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.hero{display:grid;grid-template-columns:auto 1fr;gap:20px;align-items:center;margin:18px 0}
.score{width:116px;height:116px;border-radius:50%;display:grid;place-items:center;text-align:center;
background:conic-gradient(var(--sc) calc(var(--v)*1%),var(--line) 0);position:relative}
.score::after{content:"";position:absolute;inset:9px;border-radius:50%;background:var(--bg)}
.score div{position:relative;z-index:1}.score b{font-size:30px;display:block;line-height:1}.score span{font-size:12px;color:var(--muted)}
.tiles{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px;border-top:4px solid var(--c)}
.tile b{font-size:24px;display:block}.tile span{color:var(--muted);text-transform:capitalize;font-size:13px}
.high{--c:var(--high)}.medium{--c:var(--medium)}.low{--c:var(--low)}.info{--c:var(--info)}
.summary{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;white-space:pre-wrap}
.note{border-left:3px solid var(--medium);padding:6px 12px;margin:8px 0;background:var(--card);border-radius:6px;font-size:14px}
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin-top:26px;overflow-x:auto}
.tabs button{background:none;border:0;border-bottom:2px solid transparent;color:var(--muted);padding:10px 14px;font:inherit;cursor:pointer;white-space:nowrap}
.tabs button.on{color:var(--fg);border-color:var(--fg);font-weight:600}
.panel{display:none}.panel.on{display:block}
.filters{display:flex;gap:6px;flex-wrap:wrap;margin:14px 0}
.filters button,.chip{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:99px;padding:4px 12px;font:inherit;font-size:13px;cursor:pointer}
.filters button.on{border-color:var(--fg);font-weight:600}
.filters input{flex:1;min-width:160px;background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:99px;padding:5px 12px;font:inherit;font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--c);border-radius:10px;margin:10px 0}
.card.fp{opacity:.55}
.card>summary{cursor:pointer;padding:12px 14px;display:grid;grid-template-columns:auto 1fr auto;gap:2px 10px;list-style:none;align-items:start}
.card>summary::-webkit-details-marker{display:none}
.pill{font-size:11px;font-weight:700;text-transform:uppercase;color:#fff;background:var(--c);border-radius:5px;padding:2px 7px;letter-spacing:.03em}
.t{font-weight:600}.sub{grid-column:2/4;font-size:13px;color:var(--muted)}.cnt{font-size:13px;color:var(--muted);white-space:nowrap}
.body{padding:2px 16px 16px;border-top:1px solid var(--line)}
h4{margin:16px 0 6px;font-size:14px}
pre{background:var(--code);border-radius:8px;padding:10px 12px;overflow-x:auto;font:12.5px/1.5 ui-monospace,Menlo,monospace;margin:6px 0}
pre.ref{white-space:pre-wrap;max-height:240px;overflow:auto}
.ev{border:1px solid var(--line);border-radius:8px;margin:6px 0}
.ev>summary{cursor:pointer;padding:6px 10px;font-size:13px;word-break:break-all}
.ev.fp>summary{text-decoration:line-through;color:var(--muted)}
.ev pre{margin:0 8px 8px}
.tag{font-size:11px;border:1px solid var(--line);border-radius:4px;padding:0 5px;margin-left:6px;color:var(--muted)}
ol.steps{padding-left:20px;margin:6px 0}ol.steps li{margin:3px 0}
.refs summary{cursor:pointer;color:var(--muted);margin-top:12px;font-size:14px}
table{width:100%;border-collapse:collapse;font-size:14px;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
td,th{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.file{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:10px 0}
.file>summary{cursor:pointer;padding:10px 14px;display:flex;gap:10px;align-items:center;list-style:none;flex-wrap:wrap}
.file>summary::-webkit-details-marker{display:none}
.bar{height:6px;border-radius:3px;background:var(--high);min-width:4px}
.fi{padding:8px 14px;border-top:1px solid var(--line)}
.fi .ln{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--muted)}
a{color:var(--accent)}
.kv{display:grid;grid-template-columns:200px 1fr;gap:4px 14px;font-size:14px}.kv div:nth-child(odd){color:var(--muted)}
.wrap{word-break:break-word}
@media(max-width:640px){.tiles{grid-template-columns:repeat(2,minmax(0,1fr))}.hero{grid-template-columns:1fr}.kv{grid-template-columns:1fr}
.card>summary{grid-template-columns:auto 1fr}.cnt{grid-column:2}}
"""

JS = """
const $=s=>document.querySelectorAll(s);
$('.tabs button').forEach(b=>b.onclick=()=>{$('.tabs button').forEach(x=>x.classList.toggle('on',x===b));
$('.panel').forEach(p=>p.classList.toggle('on',p.id===b.dataset.p));});
let sev='all',q='';
function apply(){$('#findings .card').forEach(c=>{const ok=(sev==='all'||c.dataset.sev===sev)&&(!q||c.textContent.toLowerCase().includes(q));
c.style.display=ok?'':'none';});}
$('#sevf button').forEach(b=>b.onclick=()=>{sev=b.dataset.s;$('#sevf button').forEach(x=>x.classList.toggle('on',x===b));apply();});
const qi=document.getElementById('q');if(qi)qi.oninput=()=>{q=qi.value.toLowerCase();apply();};
const fq=document.getElementById('fq');if(fq)fq.oninput=()=>{const v=fq.value.toLowerCase();
$('#files .file').forEach(f=>f.style.display=!v||f.textContent.toLowerCase().includes(v)?'':'none');};
$('a.jump').forEach(a=>a.onclick=()=>{document.querySelector('.tabs button[data-p=findings]').click();
const t=document.getElementById(a.getAttribute('href').slice(1));if(t){t.open=true;}});
"""


def _finding_card(f, idx):
    a = f.analysis or {}
    sev = _sev(f)
    verdict = f.verdict
    fps = _fp_locs(f)
    evs = []
    for ev in f.evidence:
        is_fp = _loc(ev) in fps or ev.location in fps
        body = f"<pre>{e(ev.context)}</pre>" if ev.context else ""
        evs.append(f"<details class='ev{' fp' if is_fp else ''}'><summary><span class=mono>{e(_loc(ev))}</span>"
                   f"{'<span class=tag>third-party</span>' if ev.third_party else ''}{'<span class=tag>false positive</span>' if is_fp else ''}"
                   f"<br><span class=muted>{e(ev.snippet[:300])}</span></summary>{body}</details>")
    steps = "".join(f"<li>{e(str(s))}</li>" for s in (a.get("fix_steps") or [f.fix]) if s)
    code = f"<pre>{e(a['fix_code'])}</pre>" if a.get("fix_code") else ""
    refs = "".join(
        f"<li><b>{e(g['title'])}</b> <span class=muted>({e(g['origin'])})</span>"
        + (f" <a href='{e(g['url'])}' target=_blank rel=noopener>open</a>" if g.get("url") else "")
        + f"<pre class=ref>{e(g['text'][:1200])}</pre></li>" for g in f.guidance)
    vlabel = verdict.replace("_", " ") if a.get("source") == "llm" else ""
    return f"""
<details class="card {sev}{' fp' if verdict == 'likely_false_positive' else ''}" id="f{idx}" data-sev="{sev}">
<summary><span class=pill>{sev}</span><span class=t>{e(f.title)}</span><span class=cnt>{len(f.evidence)} location{'s' if len(f.evidence) != 1 else ''}</span>
<span class=sub>{e(f.rule_id)} · {e(f.masvs)} · {e(f.top10)} · {e(f.cwe)}{' · <i>' + e(vlabel) + '</i>' if vlabel else ''}</span></summary>
<div class=body>
{f'<p class=note>{e(f.note)}</p>' if f.note else ''}
<h4>Risk</h4><p class=wrap>{e(a.get('risk') or '-')}</p>
{f"<h4>Attack scenario</h4><p class=wrap>{e(a['attack_scenario'])}</p>" if a.get('attack_scenario') else ''}
<h4>Where</h4>{''.join(evs)}
<h4>How to fix</h4><ol class=steps>{steps}</ol>{code}
{f"<p><b>Verify:</b> {e(a['how_to_verify'])}</p>" if a.get('how_to_verify') else ''}
<details class=refs><summary>Retrieved guidance ({len(f.guidance)})</summary><ol>{refs}</ol></details>
</div></details>"""


def write_html(result, path: Path):
    app = result.app
    active = [f for f in result.findings if f.verdict != "likely_false_positive"]
    counts = Counter(_sev(f) for f in active)
    score = app.get("score", 0)
    sc_color = "var(--ok)" if score >= 75 else "var(--medium)" if score >= 45 else "var(--high)"
    title = app.get("name") or app.get("package") or app.get("bundle_id") or Path(result.target).name
    idx_of = {id(f): i for i, f in enumerate(result.findings)}
    cards = "".join(_finding_card(f, i) for i, f in enumerate(result.findings))
    tiles = "".join(f"<div class='tile {s}'><b>{counts.get(s, 0)}</b><span>{s}</span></div>" for s in SEV_ORDER)
    notes = "".join(f"<div class=note>{e(n)}</div>" for n in result.notes)

    rows = files_view(result)
    max_r = max((r for _l, r, _t, _i in rows), default=1) or 1
    files_html = []
    for loc, risk, tp, items in rows[:400]:
        worst = _sev(items[0][0])
        lines = "".join(
            f"<div class=fi><span class='pill {_sev(f)}'>{_sev(f)}</span> <b>{e(f.title)}</b> "
            f"<span class=ln>{'line ' + str(ev.line) if ev.line else ''}</span>"
            f"<pre>{e(ev.snippet[:400])}</pre><span class=muted>Fix: {e((f.analysis or {}).get('fix_steps', [f.fix])[0] if (f.analysis or {}).get('fix_steps') else f.fix)}</span>"
            f" <a class=jump href='#f{idx_of[id(f)]}'>details</a></div>" for f, ev in items)
        files_html.append(
            f"<details class=file><summary><span class='pill {worst}'>{worst}</span><span class='mono wrap' style='flex:1'>{e(loc)}</span>"
            f"{'<span class=tag>third-party</span>' if tp else ''}<span class=muted>{len(items)} issue{'s' if len(items) != 1 else ''}</span>"
            f"<span class=bar style='width:{max(4, int(80 * risk / max_r))}px'></span></summary>{lines}</details>")
    by_masvs = Counter(f.masvs.rsplit("-", 1)[0] for f in active)
    masvs_rows = "".join(f"<tr><td>{e(k)}</td><td>{v}</td></tr>" for k, v in sorted(by_masvs.items()))

    def val(v):
        if isinstance(v, (list, tuple)):
            return e(", ".join(map(str, v))) if v else "-"
        if isinstance(v, dict):
            return e(", ".join(f"{k}: {x}" for k, x in v.items()))
        return e(str(v)) if v not in (None, "") else "-"
    kv = "".join(f"<div>{e(k.replace('_', ' '))}</div><div class='mono wrap'>{val(v)}</div>"
                 for k, v in app.items() if k not in ("score",))
    loc_word = "Locations" if result.kind in ("apk", "ipa") else "Files"
    html = f"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Mobile Security Report</title><style>{CSS}</style></head><body><main>
<div class=muted style="font-size:13px">mobsec-rag {__version__} · {dt.datetime.now():%Y-%m-%d %H:%M} · {e(str(app.get('analysis_mode', '')))}</div>
<h1 class=wrap>{e(str(title))}</h1>
<div class="muted mono wrap" style="font-size:13px">{e(result.target)} · {e(result.kind)} · {result.files_scanned} files</div>
<div class=hero><div class=score style="--v:{score};--sc:{sc_color}"><div><b>{score}</b><span>/100 · {grade(score)}</span></div></div>
<div class=tiles>{tiles}</div></div>
{notes}
<h2>Summary</h2><div class=summary>{e(result.summary)}</div>
<div class=tabs><button class=on data-p=findings>Findings ({len(result.findings)})</button>
<button data-p=files>{loc_word} with issues ({len(rows)})</button><button data-p=appinfo>App info</button></div>
<section class="panel on" id=findings>
<div class=filters id=sevf><button class=on data-s=all>All</button><button data-s=high>High</button><button data-s=medium>Medium</button>
<button data-s=low>Low</button><button data-s=info>Info</button><input id=q placeholder="Search findings, files, classes"></div>
{cards or '<p>No findings.</p>'}</section>
<section class=panel id=files><div class=filters><input id=fq placeholder="Filter {loc_word.lower()}"></div>
<p class=muted style="font-size:14px">Every {('class / file' if result.kind in ('apk', 'ipa') else 'source file')} with at least one issue, riskiest first. Expand to see each problem, the line, and how to fix it.</p>
{''.join(files_html) or '<p>No files with issues.</p>'}</section>
<section class=panel id=appinfo><h2>Application</h2><div class=kv>{kv}</div>
<h2>Findings by MASVS group</h2><table><tr><th>MASVS</th><th>Finding types</th></tr>{masvs_rows}</table></section>
<p class=muted style="margin-top:40px;font-size:13px">Static analysis with retrieval over OWASP MASVS / MASTG. Results need human review and do not replace dynamic testing. Only scan apps you own or are authorised to test.</p>
</main><script>{JS}</script></body></html>"""
    path.write_text(html)


def write_all(result, out_dir: Path, formats=("html", "json", "sarif", "md")) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {}
    writers = {"html": (write_html, "report.html"), "json": (write_json, "report.json"),
               "sarif": (write_sarif, "report.sarif"), "md": (write_markdown, "report.md")}
    for fmt in formats:
        fn, name = writers[fmt]
        fn(result, out_dir / name)
        paths[fmt] = out_dir / name
    return paths
