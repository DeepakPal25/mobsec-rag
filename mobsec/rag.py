"""Knowledge base: ingestion, chunking and hybrid retrieval (BM25 + optional embeddings).

Sources
-------
1. mobsec/knowledge/*.md   curated Android / iOS / cross-platform fix guides (always available)
2. OWASP MASTG + MASVS     cloned from GitHub by `mobsec ingest` (tests, knowledge, best practices,
                           weaknesses and the testing guide chapters for both platforms)
"""
from __future__ import annotations

import json
import math
import os
import re
import subprocess
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent
CURATED_DIR = PKG_DIR / "knowledge"


def home() -> Path:
    return Path(os.environ.get("MOBSEC_HOME", Path.home() / ".cache" / "mobsec-rag"))

EMB_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
REPOS = {"mastg": "https://github.com/OWASP/mastg", "masvs": "https://github.com/OWASP/masvs"}
MAX_CHARS = 1800


@dataclass
class Chunk:
    id: str
    title: str
    text: str
    origin: str      # curated | mastg | masvs
    platform: str    # android | ios | any
    url: str = ""


FRONT = re.compile(r"^---\n(.*?)\n---\n", re.S)


def _frontmatter(text):
    m = FRONT.match(text)
    if not m:
        return {}, text
    meta = {}
    for line in m.group(1).splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
    return meta, text[m.end():]


def _sections(body):
    parts = re.split(r"(?m)^##\s+", body)
    out = [("", parts[0].strip())] if parts[0].strip() else []
    for p in parts[1:]:
        title, _, rest = p.partition("\n")
        out.append((title.strip(), rest.strip()))
    return out


def _windows(text, size=MAX_CHARS):
    if len(text) <= size:
        yield text
        return
    buf = ""
    for para in text.split("\n\n"):
        if len(buf) + len(para) > size and buf:
            yield buf
            buf = ""
        buf += para + "\n\n"
    if buf.strip():
        yield buf


def _platform_of(rel: str, meta: dict) -> str:
    r = rel.lower()
    p = meta.get("platform", "").lower()
    if "android" in p or "/android/" in r or r.startswith(("android_", "document/0x05")):
        return "android"
    if "ios" in p or "/ios/" in r or r.startswith(("ios_", "document/0x06")):
        return "ios"
    return "any"


def chunk_markdown(path: Path, origin: str, rel: str, base_url: str = "") -> list[Chunk]:
    raw = path.read_text(errors="ignore")
    meta, body = _frontmatter(raw)
    h1 = re.search(r"(?m)^#\s+(.+)$", body)
    doc_title = meta.get("title") or (h1.group(1) if h1 else path.stem)
    prefix = " | ".join(x for x in (meta.get("id", ""), meta.get("masvs_v2_id", ""), meta.get("platform", ""),
                                     meta.get("maswe", "")) if x)
    plat = _platform_of(rel, meta)
    out = []
    for i, (sec, text) in enumerate(_sections(body)):
        text = re.sub(r"<[^>]+>", "", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        if len(text) < 80:
            continue
        for j, win in enumerate(_windows(text)):
            title = f"{doc_title} - {sec}" if sec else doc_title
            header = f"{title}\n{prefix}\n" if prefix else f"{title}\n"
            out.append(Chunk(f"{origin}:{rel}#{i}.{j}", title, header + win.strip(), origin, plat,
                             f"{base_url}/{rel}" if base_url else ""))
    return out


def clone_sources(dest: Path | None = None) -> None:
    dest = dest or home() / "src"
    dest.mkdir(parents=True, exist_ok=True)
    for name, url in REPOS.items():
        p = dest / name
        if (p / ".git").exists():
            subprocess.run(["git", "-C", str(p), "pull", "--ff-only", "-q"], check=False)
        else:
            subprocess.run(["git", "clone", "--depth", "1", "-q", url, str(p)], check=True)


MASTG_DIRS = ("tests/", "tests-beta/", "knowledge/", "best-practices/", "weaknesses/", "demos/",
              "Document/0x04", "Document/0x05", "Document/0x06")


def collect_chunks(use_owasp: bool = True) -> list[Chunk]:
    chunks = []
    for p in sorted(CURATED_DIR.glob("*.md")):
        chunks += chunk_markdown(p, "curated", p.name)
    if not use_owasp:
        return chunks
    src = home() / "src"
    mastg, masvs = src / "mastg", src / "masvs"
    if mastg.exists():
        for p in sorted(mastg.rglob("*.md")):
            rel = str(p.relative_to(mastg)).replace(os.sep, "/")
            if rel.startswith(MASTG_DIRS) and not rel.endswith(("index.md", "README.md")):
                chunks += chunk_markdown(p, "mastg", rel, "https://github.com/OWASP/mastg/blob/master")
    if masvs.exists():
        for p in sorted((masvs / "Document").rglob("*.md")):
            rel = str(p.relative_to(masvs)).replace(os.sep, "/")
            chunks += chunk_markdown(p, "masvs", rel, "https://github.com/OWASP/masvs/blob/master")
    return chunks


TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9_]+(?:-[A-Za-z0-9]+)*|\d+")


def tokenize(text: str) -> list[str]:
    toks = []
    for t in TOKEN.findall(text):
        tl = t.lower()
        toks.append(tl)
        parts = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+", t)
        if len(parts) > 1:
            toks += [p.lower() for p in parts if len(p) > 2]
        if "-" in tl:
            toks += [p for p in tl.split("-") if len(p) > 1]
    return toks


class BM25:
    def __init__(self, docs, k1=1.4, b=0.75):
        self.k1, self.b = k1, b
        self.tfs = [Counter(d) for d in docs]
        self.lens = [len(d) for d in docs]
        self.avg = sum(self.lens) / max(1, len(self.lens))
        df = Counter()
        for tf in self.tfs:
            df.update(tf.keys())
        n = len(docs)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}
        # inverted index for speed
        self.postings: dict[str, list[int]] = {}
        for i, tf in enumerate(self.tfs):
            for t in tf:
                self.postings.setdefault(t, []).append(i)

    def scores(self, query):
        s = [0.0] * len(self.tfs)
        for t, qn in Counter(query).items():
            idf = self.idf.get(t)
            if idf is None:
                continue
            for i in self.postings[t]:
                f = self.tfs[i][t]
                s[i] += idf * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * self.lens[i] / self.avg))
        return s


class KnowledgeBase:
    def __init__(self, chunks, embeddings=None):
        self.chunks = chunks
        self.bm25 = BM25([tokenize(c.text) for c in chunks])
        self.emb = embeddings

    @classmethod
    def build(cls, use_owasp=True, embed=False):
        chunks = collect_chunks(use_owasp)
        emb = _embed([c.text for c in chunks]) if embed else None
        kb = cls(chunks, emb)
        kb.save()
        return kb

    def save(self):
        home().mkdir(parents=True, exist_ok=True)
        (home() / "index.json").write_text(json.dumps([asdict(c) for c in self.chunks]))
        if self.emb is not None:
            import numpy as np
            np.save(home() / "embeddings.npy", self.emb)
        elif (home() / "embeddings.npy").exists():
            (home() / "embeddings.npy").unlink()

    @classmethod
    def load(cls):
        if not (home() / "index.json").exists():
            return cls(collect_chunks(use_owasp=False))
        chunks = [Chunk(**d) for d in json.loads((home() / "index.json").read_text())]
        emb = None
        if (home() / "embeddings.npy").exists():
            try:
                import numpy as np
                emb = np.load(home() / "embeddings.npy")
            except ImportError:
                pass
        return cls(chunks, emb)

    def search(self, query: str, k: int = 4, platform: str | None = None, boost: str | None = None):
        sc = self.bm25.scores(tokenize(query))
        for i, c in enumerate(self.chunks):
            if not sc[i]:
                continue
            if platform and c.platform not in (platform, "any"):
                sc[i] *= 0.35
            if boost and boost in c.text:
                sc[i] *= 1.3
            if c.origin == "curated":
                sc[i] *= 1.15  # curated notes carry concrete fixes
        ranked = sorted(range(len(sc)), key=lambda i: -sc[i])
        if self.emb is None:
            return [(self.chunks[i], sc[i]) for i in ranked[:k] if sc[i] > 0]
        import numpy as np
        qv = _embed([query])[0]
        dense = np.argsort(-(self.emb @ qv))
        rrf = Counter()
        for r, i in enumerate(ranked[:100]):
            rrf[i] += 1 / (60 + r)
        for r, i in enumerate(dense[:100]):
            i = int(i)
            if platform and self.chunks[i].platform not in (platform, "any"):
                continue
            rrf[i] += 1 / (60 + r)
        return [(self.chunks[i], s) for i, s in rrf.most_common(k)]

    def stats(self):
        return dict(Counter(c.origin for c in self.chunks), dense=self.emb is not None)


_MODEL = None


def _embed(texts):
    global _MODEL
    from sentence_transformers import SentenceTransformer
    if _MODEL is None:
        _MODEL = SentenceTransformer(EMB_MODEL)
    return _MODEL.encode(texts, normalize_embeddings=True, batch_size=64, show_progress_bar=len(texts) > 200)
