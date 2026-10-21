from __future__ import annotations

from dataclasses import dataclass, field, asdict

from .catalog import RULES, SEV_ORDER, downgrade


@dataclass
class Evidence:
    location: str            # file path, or class.method() for compiled code
    line: int = 0
    snippet: str = ""
    context: str = ""        # surrounding code / API calls, fed to the LLM
    third_party: bool = False


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    platform: str
    masvs: str
    top10: str
    cwe: str
    fix: str
    evidence: list = field(default_factory=list)
    note: str = ""
    guidance: list = field(default_factory=list)
    analysis: dict = field(default_factory=dict)

    @property
    def effective_severity(self) -> str:
        return (self.analysis or {}).get("severity") or self.severity

    @property
    def verdict(self) -> str:
        return (self.analysis or {}).get("verdict", "needs_review")

    def to_dict(self):
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    kind: str                 # apk | ipa | android-source | ios-source
    app: dict = field(default_factory=dict)      # metadata shown in the report header
    findings: list = field(default_factory=list)
    files_scanned: int = 0
    notes: list = field(default_factory=list)    # analysis limitations
    summary: str = ""                            # LLM executive summary

    def to_dict(self):
        d = asdict(self)
        return d


class Collector:
    """Groups evidence by rule so each rule appears once in the report."""

    def __init__(self):
        self.by_rule: dict[str, Finding] = {}

    def add(self, rule_id: str, location: str, line: int = 0, snippet: str = "", context: str = "",
            third_party: bool = False, severity: str | None = None, note: str = ""):
        meta = RULES[rule_id]
        f = self.by_rule.get(rule_id)
        if f is None:
            f = Finding(rule_id=rule_id, title=meta["title"], severity=severity or meta["severity"],
                        platform=meta["platform"], masvs=meta["masvs"], top10=meta["top10"],
                        cwe=meta["cwe"], fix=meta["fix"], note=note)
            self.by_rule[rule_id] = f
        elif severity and SEV_ORDER.index(severity) < SEV_ORDER.index(f.severity):
            f.severity = severity
        if note and not f.note:
            f.note = note
        key = (location, line, snippet[:120])
        if any((e.location, e.line, e.snippet[:120]) == key for e in f.evidence):
            return
        f.evidence.append(Evidence(location, line, snippet.strip()[:400], context[:3000], third_party))

    def results(self, max_evidence: int = 60) -> list[Finding]:
        out = []
        for f in self.by_rule.values():
            # app code first, then third-party
            f.evidence.sort(key=lambda e: (e.third_party, e.location, e.line))
            if f.evidence and all(e.third_party for e in f.evidence):
                f.severity = downgrade(f.severity)
                f.note = (f.note + " " if f.note else "") + "Only found in third-party library code."
            if len(f.evidence) > max_evidence:
                extra = len(f.evidence) - max_evidence
                f.evidence = f.evidence[:max_evidence]
                f.note = (f.note + " " if f.note else "") + f"{extra} more locations omitted."
            out.append(f)
        out.sort(key=lambda f: (SEV_ORDER.index(f.severity), f.rule_id))
        return out
