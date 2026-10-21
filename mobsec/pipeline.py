"""detect input -> analyze -> retrieve guidance -> LLM triage -> summary."""
from __future__ import annotations

import re
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .catalog import RULES, SEV_ORDER, SEV_WEIGHT
from .finding import ScanResult
from .llm import LLM, SUMMARY_SYSTEM, TRIAGE_SYSTEM, LLMError, parse_json, triage_prompt
from .rag import KnowledgeBase


def detect_kind(path: str) -> str:
    p = Path(path).expanduser()
    if p.is_dir():
        return "source"
    low = p.name.lower()
    if low.endswith((".apk", ".apks", ".xapk", ".aab")):
        return "apk"
    if low.endswith(".ipa"):
        return "ipa"
    if low.endswith(".zip") and zipfile.is_zipfile(p):
        names = zipfile.ZipFile(p).namelist()
        if "AndroidManifest.xml" in names and any(n.startswith("classes") for n in names):
            return "apk"
        if any(re.match(r"Payload/[^/]+\.app/", n) for n in names):
            return "ipa"
        return "source"
    raise ValueError(f"Unsupported input: {path} (expected .apk, .ipa, a source folder or a .zip of one)")


def analyze(path: str, include_tests: bool = False) -> ScanResult:
    kind = detect_kind(path)
    if kind == "apk":
        if path.lower().endswith(".aab"):
            raise ValueError(".aab bundles are not installable APKs; build a universal APK with bundletool first.")
        from .android.apk import analyze as run
        return run(path)
    if kind == "ipa":
        from .ios.ipa import analyze as run
        return run(path)
    from .source.scanner import scan
    return scan(path, include_tests=include_tests)


def platform_of(result: ScanResult) -> str | None:
    p = str(result.app.get("platform", "")).lower()
    if result.kind == "apk" or p == "android":
        return "android"
    if result.kind == "ipa" or p == "ios":
        return "ios"
    return None


def retrieve(kb: KnowledgeBase, finding, platform, k=3):
    meta = RULES[finding.rule_id]
    idents = []
    for e in finding.evidence[:3]:
        idents += re.findall(r"[A-Za-z_][A-Za-z0-9_]{4,}", e.snippet)[:6]
    query = f"{meta['title']} {meta['query']} {finding.masvs} {finding.cwe} {' '.join(idents)}"
    plat = meta["platform"] if meta["platform"] in ("android", "ios") else platform
    out = []
    for chunk, score in kb.search(query, k=k, platform=plat, boost=finding.masvs):
        out.append({"ref": chunk.id, "title": chunk.title, "origin": chunk.origin, "url": chunk.url,
                    "text": chunk.text[:1500], "score": round(float(score), 3)})
    return out


def offline_analysis(f) -> dict:
    expl = ""
    for g in f.guidance:
        if g["origin"] == "curated":
            body = re.sub(r"^.*\n(Tags:.*\n)?", "", g["text"], count=1)
            expl = " ".join(body.split("```")[0].split())
            break
    if not expl and f.guidance:
        expl = " ".join(f.guidance[0]["text"].split("\n", 1)[-1].split())
    if len(expl) > 700:
        expl = expl[:700].rsplit(" ", 1)[0] + " ..."
    code = ""
    for g in f.guidance:
        m = re.search(r"```(\w*)\n(.*?)```", g["text"], re.S)
        if m and g["origin"] == "curated":
            code = m.group(2).strip()
            break
    return {"verdict": "needs_review", "severity": f.severity, "risk": expl, "attack_scenario": "",
            "fix_steps": [f.fix], "fix_code": code, "fix_language": "", "how_to_verify": "",
            "false_positive_locations": [], "references": [g["ref"] for g in f.guidance[:2]], "source": "offline"}


def score(findings) -> int:
    """0-100 security score (higher is better)."""
    penalty = 0
    for f in findings:
        if f.verdict == "likely_false_positive":
            continue
        penalty += SEV_WEIGHT[f.effective_severity] * (0.5 if all(e.third_party for e in f.evidence) else 1)
    return max(0, round(100 - penalty * 1.2))


def run(path: str, llm: LLM | None = None, include_tests: bool = False, min_severity: str = "info",
        max_llm: int = 40, workers: int = 4, include_info_in_llm: bool = False, profile: str = "standard",
        log=lambda *a: print(*a, file=sys.stderr)) -> ScanResult:
    result = analyze(path, include_tests=include_tests)
    from .hardening import apply_profile
    apply_profile(result.findings, profile)
    result.app["profile"] = profile
    result.findings = [f for f in result.findings
                       if SEV_ORDER.index(f.severity) <= SEV_ORDER.index(min_severity)]
    log(f"[scan] {result.kind}: {result.files_scanned} files, {len(result.findings)} finding types, "
        f"{sum(len(f.evidence) for f in result.findings)} locations")
    kb = KnowledgeBase.load()
    log(f"[rag]  knowledge base: {len(kb.chunks)} chunks {kb.stats()}")
    plat = platform_of(result)
    for f in result.findings:
        f.guidance = retrieve(kb, f, plat)
        f.analysis = offline_analysis(f)

    llm = llm or LLM("none")
    if llm.enabled:
        todo = [f for f in result.findings if include_info_in_llm or f.severity != "info"][:max_llm]
        log(f"[llm]  triaging {len(todo)} findings with {llm.provider}:{llm.model}")

        def work(f):
            try:
                a = parse_json(llm.complete(TRIAGE_SYSTEM, triage_prompt(f, result.app, result.kind), 1800))
                a["source"] = "llm"
                if a.get("severity") not in SEV_ORDER:
                    a["severity"] = f.severity
                if not isinstance(a.get("fix_steps"), list):
                    a["fix_steps"] = [str(a.get("fix_steps", ""))]
                f.analysis = {**f.analysis, **a}
            except (LLMError, ValueError, KeyError) as e:
                log(f"[llm]  {f.rule_id}: {e}")

        with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
            list(ex.map(work, todo))
        try:
            result.summary = llm.complete(SUMMARY_SYSTEM, summary_input(result), 900).strip()
        except LLMError as e:
            log(f"[llm]  summary failed: {e}")
    result.findings.sort(key=lambda f: (f.verdict == "likely_false_positive", SEV_ORDER.index(f.effective_severity),
                                        all(e.third_party for e in f.evidence), f.rule_id))
    if not result.summary:
        result.summary = offline_summary(result)
    result.app["score"] = score(result.findings)
    result.app["analysis_mode"] = f"{llm.provider}:{llm.model}" if llm.enabled else "offline (no LLM)"
    return result


def summary_input(result: ScanResult) -> str:
    lines = [f"Scan type: {result.kind}. App: " + ", ".join(f"{k}={v}" for k, v in result.app.items()
                                                            if k in ("platform", "package", "bundle_id", "version", "min_sdk", "target_sdk", "min_os") and v)]
    for f in result.findings:
        if f.verdict == "likely_false_positive" or f.effective_severity == "info":
            continue
        locs = ", ".join(e.location + (f":{e.line}" if e.line else "") for e in f.evidence[:3])
        lines.append(f"- [{f.effective_severity}] {f.title} ({f.masvs}) at {locs}")
    return "\n".join(lines[:80])


def offline_summary(result: ScanResult) -> str:
    sev = {}
    for f in result.findings:
        sev[f.effective_severity] = sev.get(f.effective_severity, 0) + 1
    top = [f for f in result.findings if f.effective_severity in ("high", "medium")][:5]
    s = (f"Static analysis found {sev.get('high', 0)} high, {sev.get('medium', 0)} medium and {sev.get('low', 0)} low "
         f"severity issue types. Fix these first:")
    return s + "\n" + "\n".join(f"{i}. {f.title} - {f.fix}" for i, f in enumerate(top, 1))
