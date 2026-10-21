# Contributing

Thanks for helping improve mobsec-rag. Good first contributions: new detection rules, fewer false positives,
better curated fix guides, and test fixtures.

## Setup

```bash
git clone https://github.com/DeepakPal25/mobsec-rag && cd mobsec-rag
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
mobsec ingest            # optional: full OWASP knowledge base
```

## Project layout

| Path | What lives there |
|---|---|
| `mobsec/catalog.py` | Every rule: id, severity, MASVS, Mobile Top 10, CWE, retrieval query, default fix |
| `mobsec/parsers/` | Pure-Python parsers: binary XML (AXML), resources.arsc, DEX bytecode, ELF, Mach-O |
| `mobsec/android/` | APK analyzer (`apk.py`) and manifest / network-security-config checks shared with source scans |
| `mobsec/ios/` | IPA analyzer (`ipa.py`) and Info.plist / entitlement checks |
| `mobsec/source/` | Source-code scanner and its regex rules (Java, Kotlin, Gradle, Swift, ObjC, Dart, JS/TS) |
| `mobsec/rag.py` | Knowledge base ingestion, chunking, BM25 (+ optional embeddings) retrieval |
| `mobsec/llm.py` | Provider clients (Anthropic, OpenAI-compatible, Ollama) and prompts |
| `mobsec/knowledge/` | Curated fix guides used for retrieval (Markdown, one `##` section per topic) |
| `mobsec/report.py` | HTML, JSON, SARIF and Markdown output |

## Adding a rule

1. Add metadata with `R(...)` in `mobsec/catalog.py`. Pick the MASVS v2 control and a CWE.
2. Implement detection:
   - **Source code:** append an `r(...)` entry in `mobsec/source/rules.py` (regex, extensions, optional
     `requires` / `unless` / `line_unless` filters).
   - **APK:** add a check in `APKAnalyzer.code_checks()` using `self.calls("Lpkg/Class;->method")`,
     `idx.literal_calls` (constant arguments) or `idx.string_users`, and report with `self.ev(...)` so the
     finding is attributed to `class.method()`.
   - **IPA:** use `mo.imports` (imported symbols), `mo.strings` (C strings / selectors) in `IPAAnalyzer.binary_checks()`.
3. If the knowledge base lacks a good fix for the topic, add a `## section` with a `Tags:` line and a code
   example to the matching file in `mobsec/knowledge/`.
4. Add a test (see `tests/helpers.py` for builders that create synthetic manifests, Mach-O binaries, APKs and IPAs).
5. Run the scanner against a few real apps and make sure the rule does not flood results with false positives.

## Guidelines

- Keep the core dependency-free (standard library only). Optional features go behind extras.
- Prefer precision over recall for high severities; use `info` / `low` for "verify this" style checks.
- Never execute code from scanned apps, and keep all app content clearly marked as data in prompts.
- Do not commit real third-party APKs/IPAs; reference public vulnerable apps by URL instead.
