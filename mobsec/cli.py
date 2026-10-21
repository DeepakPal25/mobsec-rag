"""Command line interface.

  mobsec scan  <app.apk | app.ipa | project-dir | project.zip>  [-o out] [--llm auto|anthropic|openai|ollama|none]
  mobsec ingest [--no-owasp] [--embed]
  mobsec ask   "How do I store a refresh token securely on Android?"
  mobsec serve [--port 8765]          # local web UI: upload an APK/IPA/zip and get the report
  mobsec rules                        # list every check
"""
from __future__ import annotations

import argparse
import sys
import zipfile
import webbrowser
from pathlib import Path

from . import __version__
from .catalog import RULES, SEV_ORDER


def _llm(a):
    from .llm import LLM, LLMError
    try:
        return LLM(a.llm, a.model, a.base_url)
    except LLMError as e:
        sys.exit(f"LLM setup failed: {e}")


def cmd_scan(a):
    from .pipeline import run
    from .report import write_all
    llm = _llm(a)
    result = run(a.target, llm=llm, include_tests=a.include_tests, min_severity=a.min_severity,
                 max_llm=a.max_llm, workers=a.workers, profile=a.profile)
    out = Path(a.out)
    paths = write_all(result, out, tuple(a.format.split(",")))
    counts = {}
    for f in result.findings:
        if f.verdict != "likely_false_positive":
            counts[f.effective_severity] = counts.get(f.effective_severity, 0) + 1
    print(f"\nScore {result.app.get('score')}/100 | " + ", ".join(f"{counts.get(s, 0)} {s}" for s in SEV_ORDER))
    for f in result.findings[:12]:
        if f.verdict == "likely_false_positive":
            continue
        ev = f.evidence[0]
        loc = f"{ev.location}:{ev.line}" if ev.line else ev.location
        print(f"  [{f.effective_severity:6}] {f.title}  ->  {loc}" + (f" (+{len(f.evidence) - 1})" if len(f.evidence) > 1 else ""))
    print("\nReports:\n" + "\n".join(f"  {p}" for p in paths.values()))
    if a.open and "html" in paths:
        webbrowser.open(paths["html"].resolve().as_uri())
    if a.fail_on:
        limit = SEV_ORDER.index(a.fail_on)
        if any(SEV_ORDER.index(f.effective_severity) <= limit and f.verdict != "likely_false_positive"
               and not all(e.third_party for e in f.evidence) for f in result.findings):
            sys.exit(2)


def cmd_ingest(a):
    from .rag import KnowledgeBase, clone_sources, home
    if not a.no_owasp:
        print("Cloning / updating OWASP MASTG and MASVS ...", file=sys.stderr)
        clone_sources()
    if a.embed:
        try:
            import sentence_transformers  # noqa: F401
        except ImportError:
            sys.exit("--embed needs: pip install 'mobsec-rag[embeddings]'")
    kb = KnowledgeBase.build(use_owasp=not a.no_owasp, embed=a.embed)
    print(f"Indexed {len(kb.chunks)} chunks {kb.stats()} into {home()}")


def cmd_ask(a):
    from .llm import QA_SYSTEM
    from .rag import KnowledgeBase
    kb = KnowledgeBase.load()
    hits = kb.search(a.question, k=a.k, platform=a.platform)
    passages = [{"ref": c.id, "title": c.title, "text": c.text[:1600], "url": c.url} for c, _ in hits]
    llm = _llm(a)
    if llm.enabled:
        refs = "\n\n".join(f"[{p['ref']}] {p['title']}\n{p['text']}" for p in passages)
        print(llm.complete(QA_SYSTEM, f"<references>\n{refs}\n</references>\n\nQuestion: {a.question}"))
        print("\nSources:")
        for p in passages:
            print(f"- [{p['ref']}] {p['title']} {p['url']}")
    else:
        print("(offline mode: most relevant passages)\n")
        for p in passages:
            print(f"## {p['title']}  [{p['ref']}] {p['url']}\n{p['text'][:900]}\n")


def cmd_rules(a):
    for rid, r in sorted(RULES.items(), key=lambda x: (x[1]["platform"], SEV_ORDER.index(x[1]["severity"]), x[0])):
        if a.platform and r["platform"] not in (a.platform, "any"):
            continue
        print(f"{rid:28} {r['platform']:8} {r['severity']:6} {r['masvs']:20} {r['title']}")
    print(f"\n{len(RULES)} rules")


def cmd_serve(a):
    from .web import serve
    serve(a.host, a.port, _llm(a), open_browser=not a.no_browser)


def main(argv=None):
    p = argparse.ArgumentParser(prog="mobsec", description="RAG-assisted security scanner for Android and iOS apps")
    p.add_argument("--version", action="version", version=f"mobsec-rag {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def llm_args(sp):
        sp.add_argument("--llm", default="auto", choices=["auto", "anthropic", "openai", "ollama", "none"],
                        help="LLM provider (auto picks Anthropic, then OpenAI, else offline)")
        sp.add_argument("--model", help="model name (default depends on provider)")
        sp.add_argument("--base-url", help="custom OpenAI-compatible endpoint, e.g. http://localhost:11434/v1")

    s = sub.add_parser("scan", help="scan an APK, IPA, or Android/iOS source folder (or .zip)")
    s.add_argument("target")
    s.add_argument("-o", "--out", default="mobsec-report")
    s.add_argument("--format", default="html,json,sarif,md", help="comma list of html,json,sarif,md")
    s.add_argument("--min-severity", default="info", choices=SEV_ORDER)
    s.add_argument("--include-tests", action="store_true", help="also scan test folders (source mode)")
    s.add_argument("--max-llm", type=int, default=40, help="max findings sent to the LLM")
    s.add_argument("--workers", type=int, default=4, help="parallel LLM requests")
    s.add_argument("--fail-on", choices=["high", "medium", "low"], help="exit 2 if app-code findings at this level exist (CI)")
    s.add_argument("--open", action="store_true", help="open the HTML report when done")
    s.add_argument("--profile", default="standard", choices=["standard", "high-risk"],
                   help="high-risk (banking, health, payments, DRM): missing hardening controls are rated medium")
    llm_args(s)
    s.set_defaults(fn=cmd_scan)

    i = sub.add_parser("ingest", help="download OWASP MASTG/MASVS and build the knowledge base")
    i.add_argument("--no-owasp", action="store_true", help="index only the bundled curated notes")
    i.add_argument("--embed", action="store_true", help="add dense embeddings (needs extra 'embeddings')")
    i.set_defaults(fn=cmd_ingest)

    q = sub.add_parser("ask", help="ask a mobile security question answered from the knowledge base")
    q.add_argument("question")
    q.add_argument("-k", type=int, default=5)
    q.add_argument("--platform", choices=["android", "ios"])
    llm_args(q)
    q.set_defaults(fn=cmd_ask)

    w = sub.add_parser("serve", help="local web UI for uploading APK / IPA / source zip")
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=8765)
    w.add_argument("--no-browser", action="store_true")
    llm_args(w)
    w.set_defaults(fn=cmd_serve)

    r = sub.add_parser("rules", help="list all checks")
    r.add_argument("--platform", choices=["android", "ios"])
    r.set_defaults(fn=cmd_rules)

    a = p.parse_args(argv)
    try:
        a.fn(a)
    except (ValueError, FileNotFoundError, zipfile.BadZipFile) as e:
        sys.exit(f"mobsec: error: {e}")
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
