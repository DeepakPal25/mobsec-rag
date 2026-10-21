# mobsec-rag

**Open-source security scanner for Android and iOS apps that explains every risk and how to fix it, grounded in OWASP MASVS / MASTG through retrieval-augmented generation (RAG).**

Give it any of:

| Input | What it analyses |
|---|---|
| **`.apk`** (also `.apks` / `.xapk`) | AndroidManifest, network security config, **DEX bytecode** (per `class.method()`), native `.so` libraries, signing scheme and certificate, resources and assets |
| **`.ipa`** | Info.plist, entitlements, **Mach-O binary** (PIE, canary, ARC, encryption, imported APIs, strings), embedded frameworks, bundle resources |
| **Source folder or `.zip`** | Java, Kotlin, Gradle, AndroidManifest/XML, Swift, Objective-C, plist/entitlements, Dart (Flutter), JS/TS (React Native): **every vulnerable file with line numbers** |

For each issue you get the severity, where it is (file + line, or class + method), why it is risky, a realistic attack scenario, step-by-step fix with code, how to verify, and links to the OWASP guidance it was based on.

```
 APK / IPA / source
        │
        ▼
 ┌──────────────────┐  findings + code context  ┌───────────────┐  top passages  ┌──────────────┐
 │ static analyzers │ ────────────────────────▶ │   retriever   │ ─────────────▶ │  LLM triage  │ ──▶ HTML · JSON · SARIF · Markdown
 │ 125 checks       │                           │ BM25 (+dense) │                │  (optional)  │
 └──────────────────┘                           └───────────────┘                └──────────────┘
                                                        ▲
                                  OWASP MASTG + MASVS + curated fix guides (~2,850 chunks)
```

## Why mobsec-rag?

Most mobile static analyzers stop at "here's a pattern match on line 42." That tells you *what* was found but not *why it matters*, *how an attacker would actually exploit it*, or *what the fix should look like for this specific codebase*. mobsec-rag is built to close that gap:

- It runs **109 purpose-built checks** against the compiled artifact (APK/IPA) or the raw source tree, not just a generic linter ruleset — including bytecode-level checks (decompiled DEX, Mach-O disassembly) that source-only scanners miss entirely.
- Every finding is **grounded in OWASP's own guidance**. Instead of inventing an explanation, it retrieves the exact MASVS requirement and MASTG test case that applies, via retrieval-augmented generation (RAG) over a locally built knowledge base of ~2,850 chunks.
- An **optional LLM triage step** reads the finding plus the retrieved OWASP passages plus the surrounding code, and produces an app-specific attack scenario, a concrete fix (with code), and a false-positive call — rather than a canned description that's identical for every app.
- It runs **fully offline by default**. Nothing is required to leave your machine; LLM triage is opt-in and only activates if you provide an API key or point it at a local Ollama model.

## How it works

```
   1. INPUT                2. STATIC ANALYSIS          3. RETRIEVAL                 4. TRIAGE (optional)        5. REPORT
 ──────────────           ─────────────────────      ──────────────────          ──────────────────────      ──────────────
 .apk / .ipa /     ───▶   Parse the artifact in-     For each finding, build  ───▶ LLM reads the finding +    HTML, JSON,
 source folder             process (no decompiler     a query from its rule        code context + OWASP        SARIF, Markdown
 or .zip                   shell-out): AndroidManifest, type/location/code and      passages and writes an
                           DEX bytecode, native .so,   run it against the RAG      app-specific explanation,
                           Mach-O binary, Info.plist,  index (BM25, optionally     attack scenario, fix code,
                           source files per language.  fused with dense embeddings  and a true/false-positive
                           109 checks flag issues      via reciprocal rank fusion) verdict. Skipped entirely
                           with severity + location.   over the OWASP MASTG/MASVS  in offline mode.
                                                        corpus + curated fix guides.
```

Concretely, a scan (`mobsec scan app.apk`) does:

1. **Parse** — the APK/IPA is unpacked and parsed directly in Python: the manifest/plist, the DEX bytecode is disassembled method-by-method, native ELF `.so` and Mach-O binaries are inspected for protections (PIE, stack canary, ARC, encryption) and strings, resources/`.arsc` and XML are decoded. Source-folder scans walk the tree and parse each file (Java/Kotlin/Gradle, Swift/Obj-C, Dart, JS/TS) with lightweight per-language rule engines in `mobsec/source/rules.py`.
2. **Detect** — each of the 109 checks runs against that parsed structure and emits a `Finding` (`mobsec/finding.py`) with a severity, a precise location (file + line, or class + method for bytecode), and the rule that fired. Findings inside third-party/vendored libraries are detected and down-weighted so your own app code surfaces first.
3. **Retrieve** — `mobsec/rag.py` turns each finding into a query and ranks the pre-ingested OWASP MASTG + MASVS knowledge base (built once via `mobsec ingest` into `mobsec/knowledge/`) with BM25, optionally fused with dense embeddings if you installed the `embeddings` extra. The top passages are attached to the finding as grounding.
4. **Triage (optional)** — if an LLM is configured (`mobsec/llm.py`), each finding plus its code context plus the retrieved passages is sent to the model, which returns a tailored explanation, a realistic attack scenario, fix code, and a true/false-positive verdict. With `--llm none` this step is skipped and reports use the static template text instead — the scan is complete either way.
5. **Report** — `mobsec/report.py` renders the findings into `report.html` / `.json` / `.sarif` / `.md`, plus app metadata (permissions, exported components, binary protections, dependencies) collected during parsing.

## Project structure

```
mobsec/
├── cli.py              # `mobsec` command entrypoint (scan, ingest, ask, serve, rules)
├── pipeline.py          # orchestrates parse → detect → retrieve → triage → report for one scan
├── finding.py           # the Finding data model shared by every check
├── catalog.py           # the 109-rule catalog (id, severity, MASVS/CWE mapping)
├── rag.py               # BM25 / hybrid retrieval over the OWASP knowledge base
├── llm.py               # optional LLM clients (Anthropic, OpenAI-compatible, Ollama)
├── report.py            # HTML / JSON / SARIF / Markdown report rendering
├── secrets.py           # hardcoded-secret detection (API keys, tokens, credentials)
├── web.py               # `mobsec serve` local drag-and-drop web UI
├── android/             # AndroidManifest + manifest-derived checks
│   ├── apk.py           #   APK container parsing (zip, signing, resources)
│   └── manifest.py      #   manifest/XML analysis (exported components, permissions)
├── ios/                 # Info.plist / entitlements / Mach-O checks
│   ├── ipa.py           #   IPA container parsing
│   └── plist_checks.py  #   Info.plist and entitlement analysis
├── parsers/             # low-level binary format parsers (stdlib only)
│   ├── dex.py           #   DEX bytecode disassembly
│   ├── axml.py           #   Android binary XML decoding
│   ├── arsc.py            #   Android compiled resources decoding
│   ├── elf.py              #   native .so (ELF) inspection
│   └── macho.py            #   Mach-O binary inspection
├── source/              # source-tree (non-binary) scanning
│   ├── scanner.py        #   walks a source folder/zip and dispatches per file type
│   └── rules.py          #   per-language rule checks (Java/Kotlin/Swift/Dart/JS/TS)
└── knowledge/            # OWASP MASTG/MASVS corpus + curated fix guides (built by `mobsec ingest`)

tests/                    # pytest suite: parsers, analyzers, full pipeline
docs/RULES.md             # full list of the 109 checks with MASVS/CWE mapping
action.yml                 # GitHub Action wrapper (used in CI usage below)
Dockerfile                  # container build for `docker run mobsec-rag scan ...`
```

## Quick start

```bash
pip install git+https://github.com/DeepakPal25/mobsec-rag   # or: pip install -e . from a clone
mobsec ingest                 # one-time: download OWASP MASTG + MASVS and build the knowledge base

mobsec scan app.apk --open                # Android binary
mobsec scan app.ipa --open                # iOS binary
mobsec scan ./MyAndroidProject --open     # Android / iOS / Flutter / React Native source
mobsec serve                              # local web page: drag in an APK, IPA or source .zip
```

Python 3.10+. **No required dependencies**: parsers, retrieval and LLM clients use only the standard library.

### LLM options (all optional)

The scanner, retrieval and reports work fully offline. An LLM adds per-finding triage (true/false positive), app-specific explanations, attack scenarios, tailored fix code, and an executive summary.

| Provider | Setup | Data leaves your machine? |
|---|---|---|
| none | `--llm none` | No |
| **Ollama (local)** | `ollama pull llama3.1` then `--llm ollama --model llama3.1` | **No** |
| Anthropic Claude | `export ANTHROPIC_API_KEY=...` then `--llm anthropic` | Yes (snippets, class names, strings) |
| OpenAI or any compatible API | `export OPENAI_API_KEY=...` then `--llm openai [--base-url ...]` | Yes |

`--llm auto` (the default) uses Anthropic if its key is set, then OpenAI, else offline.

## Hardening profile

Apps differ in how much reverse-engineering protection they need. By default, missing hardening controls are rated `info` / `low`. For banking, health, payments, DRM or games with in-app economies, use:

```bash
mobsec scan app.apk --profile high-risk
```

This rates every missing MASVS-RESILIENCE control as `medium`, matching what OWASP MASVS-R expects for high-risk apps. The fix guidance includes R8 configuration, Kotlin and Swift snippets for anti-debugging, Frida detection, signature and installer checks, Play Integrity and App Attest, tapjacking and screen-capture protection, and release build settings for stripping symbols.

## Reports

Each scan writes `report.html`, `report.json`, `report.sarif` and `report.md`:

- **Overview:** security score (0-100), counts by severity, executive summary.
- **Findings:** one card per issue type with risk, attack scenario, every location (with surrounding code), fix steps, fix code, verification, and the retrieved OWASP passages.
- **Files / locations with issues:** every file (source) or class (APK) that has a problem, riskiest first, each problem with its line and fix.
- **Hardening:** a checklist of every protection control, present or missing, with the evidence found and a link to the fix.
- **App info:** package/bundle, SDK/OS levels, permissions, exported components, binary protections, frameworks, SDKs, dependencies.
- **SARIF** works with GitHub code scanning; **JSON** has a `files` section for tooling.

## What it checks

125 checks mapped to OWASP MASVS v2, Mobile Top 10 (2024) and CWE. Full list: [docs/RULES.md](docs/RULES.md) or `mobsec rules`.

- **Storage:** secrets in SharedPreferences / UserDefaults / AsyncStorage, world-readable files, external storage, unencrypted DBs, weak Keychain classes, `NSFileProtectionNone`, backups, logs, clipboard, file sharing.
- **Crypto:** ECB / DES / RC4, RSA without OAEP, unauthenticated CBC, MD5/SHA-1, hardcoded keys and static IVs (including keys held in class fields), weak or seeded RNGs.
- **Network:** cleartext traffic, NSC user CAs / `overridePins`, trust-all TrustManagers (detected from bytecode), hostname verifiers returning `true`, WebView `proceed()` on SSL errors, ATS exceptions, iOS trust bypasses, Flutter `badCertificateCallback`, missing pinning.
- **Platform / IPC:** exported activities, services, receivers and providers without permissions, weak custom permissions, deep links, task hijacking, intent redirection, implicit broadcasts, mutable PendingIntents, URL schemes, WebView JS bridges and file access.
- **Code:** SQL injection (Android bytecode, Swift interpolation fragments in Mach-O, source), command execution, dynamic code loading, Zip Slip, eval.
- **Auth:** biometrics without `CryptoObject` / `SecAccessControl`.
- **Resilience and build:** debuggable, `get-task-allow`, testOnly, debug certificates, v1-only signing (Janus), R8 disabled, PIE / canary / ARC / NX / RELRO, unstripped symbols, root/jailbreak detection and attestation presence, FLAG_SECURE.
- **Hardening / anti-reverse-engineering (MASVS-RESILIENCE):** code obfuscation (R8/ProGuard, readable class and type names), source file names left in DEX, stripped symbols (DEX, `.so`, Mach-O), root and jailbreak detection, anti-debugging (JDWP, TracerPid, ptrace / sysctl), Frida / Xposed / Substrate hooking detection, emulator detection, anti-tampering (signature, installer, re-signing checks), Play Integrity / App Attest attestation, tapjacking / overlay protection, screenshot and screen-recording protection, plaintext secrets, and detection of RASP SDKs and packers (freeRASP, Approov, DexGuard, Promon, Appdome, Jiagu, Bangcle, Legu and others).
- **Secrets:** AWS, Google, Stripe, Slack, GitHub, OpenAI/Anthropic, SendGrid, private keys, JWTs, credentials in URLs, hardcoded password comparisons, Gradle signing passwords, bundled keystores, Firebase and cloud bucket URLs.
- **Privacy:** dangerous permissions, tracker SDKs, missing iOS privacy manifest.

Binary findings in third-party libraries are labelled and down-weighted so app code comes first.

## Validation

Tested against intentionally vulnerable public apps (offline mode, no LLM):

| Target | Type | Files | High / Med / Low / Info | Locations | Time |
|---|---|---|---|---|---|
| InsecureBankv2.apk | apk | 555 | 4 / 9 / 8 / 5 | 49 | 2.5s |
| MASTG-Playground.apk | apk | 389 | 3 / 10 / 6 / 5 | 48 | 1.7s |
| DVIA-v2.ipa | ipa | 231 | 2 / 5 / 6 / 5 | 37 | 1.7s |
| iGoat-Swift.ipa | ipa | 243 | 2 / 7 / 4 / 5 | 23 | 1.3s |
| Android-InsecureBankv2 | source | 69 | 3 / 8 / 6 / 3 | 87 | 1.3s |
| diva-android | source | 52 | 2 / 7 / 4 / 4 | 37 | 1.2s |
| iGoat-Swift | source | 304 | 4 / 5 / 2 / 6 | 37 | 4.0s |
| DVIA-v2 | source | 285 | 2 / 4 / 3 / 5 | 45 | 3.9s |

Examples of what it pinpoints: InsecureBank's AES key held in a field of `CryptoClass` and used in `aes256encrypt()`, `MODE_WORLD_READABLE` prefs in `MyBroadCastReceiver.onReceive()`, credentials saved in `DoLogin.saveCreds()`; MASTG's SQL injection in `OMTG_CODING_003_SQL_Injection.checkLogin()` and its content provider `query()`; iGoat's `LIKE '\(searchStr)'` SQL fragment in the compiled Swift binary; DIVA's `equals("vendorsecretkey")` check.

## CI usage

GitHub Action (uploads SARIF to code scanning):

```yaml
- uses: DeepakPal25/mobsec-rag@v0
  with:
    target: app/build/outputs/apk/release/app-release.apk
    fail-on: high
```

Any CI: `mobsec scan <target> --fail-on high --format sarif,json` exits with code 2 when app-code findings at that level remain.

Docker: `docker build -t mobsec-rag .` then `docker run --rm -v "$PWD:/work" mobsec-rag scan app.apk -o report`.

## Ask questions

```bash
mobsec ask "How do I store a refresh token securely and require Face ID?" --platform ios
```

Answers come only from the knowledge base, with citations.

## Optional hybrid retrieval

```bash
pip install "mobsec-rag[embeddings]"
mobsec ingest --embed      # adds dense embeddings, fused with BM25 by reciprocal rank fusion
```

## Limitations

- Static analysis only. Confirm runtime behaviour (pinning, trust evaluation, biometric bypass) with dynamic testing: an intercepting proxy, Frida / objection.
- App Store IPAs are FairPlay-encrypted; scan a development, ad-hoc or enterprise build for full results.
- Flutter Dart code (`libapp.so`) and Hermes bytecode are checked for strings and secrets only.
- `.aab` must be converted to a universal APK with `bundletool` first; split APKs: only the base APK is analysed.
- Some checks are "verify this" heuristics (`info` / `low`). The optional LLM step marks likely false positives, but human review is still needed.

## Responsible use

Only scan apps you own or are authorised to test. See [SECURITY.md](SECURITY.md).

## Contributing

Rules, curated fix guides and false-positive reports are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. The OWASP MASTG and MASVS content downloaded by `mobsec ingest` is CC BY-SA 4.0 by OWASP.
