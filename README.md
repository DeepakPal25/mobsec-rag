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
 │ 109 checks       │                           │ BM25 (+dense) │                │  (optional)  │
 └──────────────────┘                           └───────────────┘                └──────────────┘
                                                        ▲
                                  OWASP MASTG + MASVS + curated fix guides (~2,850 chunks)
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

## Reports

Each scan writes `report.html`, `report.json`, `report.sarif` and `report.md`:

- **Overview:** security score (0-100), counts by severity, executive summary.
- **Findings:** one card per issue type with risk, attack scenario, every location (with surrounding code), fix steps, fix code, verification, and the retrieved OWASP passages.
- **Files / locations with issues:** every file (source) or class (APK) that has a problem, riskiest first, each problem with its line and fix.
- **App info:** package/bundle, SDK/OS levels, permissions, exported components, binary protections, frameworks, SDKs, dependencies.
- **SARIF** works with GitHub code scanning; **JSON** has a `files` section for tooling.

## What it checks

109 checks mapped to OWASP MASVS v2, Mobile Top 10 (2024) and CWE. Full list: [docs/RULES.md](docs/RULES.md) or `mobsec rules`.

- **Storage:** secrets in SharedPreferences / UserDefaults / AsyncStorage, world-readable files, external storage, unencrypted DBs, weak Keychain classes, `NSFileProtectionNone`, backups, logs, clipboard, file sharing.
- **Crypto:** ECB / DES / RC4, RSA without OAEP, unauthenticated CBC, MD5/SHA-1, hardcoded keys and static IVs (including keys held in class fields), weak or seeded RNGs.
- **Network:** cleartext traffic, NSC user CAs / `overridePins`, trust-all TrustManagers (detected from bytecode), hostname verifiers returning `true`, WebView `proceed()` on SSL errors, ATS exceptions, iOS trust bypasses, Flutter `badCertificateCallback`, missing pinning.
- **Platform / IPC:** exported activities, services, receivers and providers without permissions, weak custom permissions, deep links, task hijacking, intent redirection, implicit broadcasts, mutable PendingIntents, URL schemes, WebView JS bridges and file access.
- **Code:** SQL injection (Android bytecode, Swift interpolation fragments in Mach-O, source), command execution, dynamic code loading, Zip Slip, eval.
- **Auth:** biometrics without `CryptoObject` / `SecAccessControl`.
- **Resilience and build:** debuggable, `get-task-allow`, testOnly, debug certificates, v1-only signing (Janus), R8 disabled, PIE / canary / ARC / NX / RELRO, unstripped symbols, root/jailbreak detection and attestation presence, FLAG_SECURE.
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
