"""Secret / credential detection shared by every scanner."""
from __future__ import annotations

import math
import re

# (name, regex, severity)
PATTERNS = [
    ("AWS access key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "medium"),
    ("Google OAuth client secret", re.compile(r"\bGOCSPX-[0-9A-Za-z\-_]{28}\b"), "high"),
    ("Stripe secret key", re.compile(r"\b(sk|rk)_live_[0-9a-zA-Z]{16,}\b"), "high"),
    ("Stripe publishable key", re.compile(r"\bpk_live_[0-9a-zA-Z]{16,}\b"), "info"),
    ("Slack token", re.compile(r"\bxox[abposr]-[0-9A-Za-z-]{10,}\b"), "high"),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}"), "high"),
    ("GitHub token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{30,}\b"), "high"),
    ("Twilio API key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "medium"),
    ("SendGrid API key", re.compile(r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b"), "high"),
    ("Mailgun API key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), "medium"),
    ("OpenAI API key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9_-]{32,}\b"), "high"),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}\b"), "high"),
    ("Private key", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"), "high"),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "medium"),
    ("Basic auth in URL", re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@\"']{3,}:[^/\s:@\"']{3,}@[\w.-]+"), "high"),
    ("Azure storage key", re.compile(r"AccountKey=[A-Za-z0-9+/=]{60,}"), "high"),
    ("Facebook access token", re.compile(r"\bEAACEdEose0cBA[0-9A-Za-z]+\b"), "high"),
]

FIREBASE = re.compile(r"https?://[a-z0-9-]+\.(firebaseio\.com|firebasedatabase\.app)")
BUCKET = re.compile(r"(https?://[a-z0-9.-]+\.s3[.-][a-z0-9.-]*amazonaws\.com[^\s\"']*|"
                    r"https?://s3[.-][a-z0-9-]*\.amazonaws\.com/[a-z0-9.-]+|"
                    r"https?://storage\.googleapis\.com/[a-z0-9._-]+|"
                    r"https?://[a-z0-9-]+\.blob\.core\.windows\.net)")

# variable-style assignments in source / config: password = "....."
ASSIGN = re.compile(
    r"""(?ix)\b([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|
    client[_-]?secret|private[_-]?key|encryption[_-]?key|aes[_-]?key)[A-Za-z0-9_.-]*)\b
    \s*(?:[:=]|=>|\bto\b)\s*(?:String\s*=\s*)?@?["']([^"'\s]{6,})["']""")

PLACEHOLDER = re.compile(r"(?i)^(\*+|x+|your[_-]?|change[_-]?me|example|placeholder|null|none|true|false|"
                         r"test|password|secret|\$\{|%@|%s|<|@string/)")


def entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in freq.values())


NOT_SECRET_NAME = re.compile(r"(?i)(pattern|regex|format|hint|label|field|param|placeholder|prompt|message|title|"
                             r"error|text|name|type|header|url|path|endpoint|_key$|key_?name|prefkey|keyname|column|"
                             r"intent|action|extra|tag|policy|template|validator|description|class)$")
REGEX_LIKE = re.compile(r"[\\^$()\[\]{}|*+?]{3,}|\(\?=")


def scan_text(text: str, assignments: bool = True):
    """Yield (kind, matched_value, severity, offset)."""
    for name, rx, sev in PATTERNS:
        for m in rx.finditer(text):
            yield name, m.group(0), sev, m.start()
    if assignments:
        for m in ASSIGN.finditer(text):
            val = m.group(2)
            if PLACEHOLDER.match(val) or NOT_SECRET_NAME.search(m.group(1)) or REGEX_LIKE.search(val):
                continue
            yield f"Hardcoded value for '{m.group(1)}'", val, "high" if entropy(val) > 3.0 else "medium", m.start()


def mask(value: str) -> str:
    if len(value) <= 8:
        return value[:2] + "*" * (len(value) - 2)
    return value[:6] + "…" + value[-4:]
