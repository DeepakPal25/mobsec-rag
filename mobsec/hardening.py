"""Hardening / anti-reverse-engineering assessment (OWASP MASVS-RESILIENCE).

Produces a checklist of protection controls with status present / missing for APK, IPA and source
scans, and raises a finding for each missing control so it gets retrieved guidance and fix steps.
"""
from __future__ import annotations

import re

RESILIENCE_RULES = {
    "AND-NOT-OBFUSCATED", "AND-DEBUG-INFO-RETAINED", "AND-NO-ROOT-DETECTION", "AND-NO-ANTI-DEBUG",
    "AND-NO-HOOK-DETECTION", "AND-NO-EMULATOR-DETECTION", "AND-NO-TAMPER-CHECK", "AND-NO-ATTESTATION",
    "AND-NO-TAPJACKING-PROTECTION", "AND-NO-FLAG-SECURE", "AND-NO-STRING-ENCRYPTION", "AND-NATIVE-NOT-STRIPPED",
    "IOS-NOT-OBFUSCATED", "IOS-NOT-STRIPPED", "IOS-NO-JB-DETECTION", "IOS-NO-ANTI-DEBUG", "IOS-NO-HOOK-DETECTION",
    "IOS-NO-TAMPER-CHECK", "IOS-NO-ATTESTATION", "IOS-NO-SCREEN-PROTECTION", "AND-NO-PINNING", "IOS-NO-PINNING",
}

# --------------------------------------------------------------- shared indicator patterns
ROOT_RX = re.compile(r"(/system/xbin/su|/system/bin/su|/sbin/su|Superuser\.apk|com\.topjohnwu\.magisk|eu\.chainfire\.supersu|"
                     r"test-keys|com\.noshufou\.android\.su|RootBeer|isDeviceRooted|isRooted|com\.koushikdutta\.superuser|"
                     r"/data/local/xbin|magisk)", re.I)
ANTI_DEBUG_RX = re.compile(r"(TracerPid|isDebuggerConnected|waitingForDebugger|adb_enabled|development_settings_enabled|"
                           r"PT_DENY_ATTACH|P_TRACED|amIDebugged|denyDebugger|isDebuggerAttached|antiDebug|jdwp)", re.I)
HOOK_RX = re.compile(r"(frida|gum-js-loop|\bgmain\b|linjector|\b27042\b|xposed|de\.robv\.android|lsposed|edxposed|"
                     r"\bsubstrate|cydia ?substrate|\briru\b|zygisk|cynject|libcycript|SubstrateLoader|substitute-inserter|"
                     r"amIRuntimeHooked|amIReverseEngineered|amIProxied|hookdetect|isHooked)", re.I)
EMU_RX = re.compile(r"(\bgoldfish\b|\branchu\b|sdk_gphone|generic_x86|\bvbox86|genymotion|\bnox(player)?\b|bluestacks|"
                    r"ro\.kernel\.qemu|qemu\.hw|isEmulator|amIRunInEmulator|SIMULATOR_DEVICE_NAME|ldplayer|\bmemu\b|"
                    r"Build\.FINGERPRINT\.startsWith|checkIfDeviceIsEmulator)", re.I)
TAMPER_RX = re.compile(r"(GET_SIGNING_CERTIFICATES|getApkContentsSigners|getSigningCertificateHistory|GET_SIGNATURES|"
                       r"getInstallerPackageName|getInstallSourceInfo|verifyAppSignature|checkAppSignature|appIntegrity|"
                       r"embedded\.mobileprovision|SignerIdentity|amITampered|isTampered|checksum.*classes\.dex)", re.I)
ATTEST_RX = re.compile(r"(IntegrityManager|play\.core\.integrity|PlayIntegrity|SafetyNet|DCAppAttestService|DCDevice|AppAttest)")
TAPJACK_RX = re.compile(r"(filterTouchesWhenObscured|setFilterTouchesWhenObscured|setHideOverlayWindows|HIDE_OVERLAY_WINDOWS|"
                        r"FLAG_WINDOW_IS_(PARTIALLY_)?OBSCURED)")
SCREEN_IOS_RX = re.compile(r"(isCaptured|capturedDidChange|UIScreenCapturedDidChangeNotification|userDidTakeScreenshot|"
                           r"UIApplicationUserDidTakeScreenshotNotification|isSecureTextEntry.*snapshot|preventScreenCapture)")

# Known protectors / RASP SDKs: (name, regex over class names, file names or strings)
PROTECTORS = [
    ("Talsec freeRASP", r"com/aheaditec/talsec|TalsecRuntime|freerasp"),
    ("Approov", r"io/approov|io\.approov|Approov"),
    ("Guardsquare DexGuard", r"com/guardsquare/dexguard|libdexguard"),
    ("Promon SHIELD", r"promon|libshield"),
    ("Appdome", r"appdome"),
    ("Zimperium zDefend", r"com/zimperium"),
    ("Digital.ai / Arxan", r"arxan|com/digitalai"),
    ("OneSpan / Vasco", r"com/vasco|onespan"),
    ("Liapp", r"liapp"),
    ("RootBeer", r"com/scottyab/rootbeer"),
    ("IOSSecuritySuite", r"IOSSecuritySuite"),
    ("Qihoo 360 Jiagu (packer)", r"libjiagu"),
    ("Bangcle / SecNeo (packer)", r"libsecexe|libDexHelper|libsecmain"),
    ("Tencent Legu (packer)", r"libshella|libtup\.so|libshell-super"),
    ("Ijiami (packer)", r"libexecmain|ijiami"),
    ("Baidu protect (packer)", r"libbaiduprotect"),
]
PACKERS = {name for name, _ in PROTECTORS if "packer" in name}


def _first(rx, strings, limit=200):
    for s in strings:
        if len(s) <= limit:
            m = rx.search(s)
            if m:
                return s[:120]
    return None


def detect_protectors(haystack: list[str]) -> list[str]:
    found = []
    for name, pat in PROTECTORS:
        rx = re.compile(pat, re.I)
        if any(rx.search(h) for h in haystack):
            found.append(name)
    return found


def _row(control, ok, evidence, rule, missing_msg):
    return {"control": control, "status": "present" if ok else "missing",
            "evidence": evidence if ok else missing_msg, "rule": rule}


# =============================================================== Android (APK)
def android_apk(an) -> dict:
    """`an` is an APKAnalyzer after code_checks(). Adds findings and returns the hardening profile."""
    idx, c = an.idx, an.c
    strings = list(idx.strings)
    classes = list(idx.classes)
    names = an.names
    haystack = classes + names + [s for s in strings if len(s) < 120]
    protectors = detect_protectors(haystack)
    packed = [p for p in protectors if p in PACKERS]
    if packed:
        c.add("AND-PACKED", "lib/", 0, ", ".join(packed))
        an.notes.append(f"App is packed with {', '.join(packed)}: the real DEX is decrypted at runtime, so code "
                        "checks only see the loader. Scan the unprotected build for full results.")
    rows = []
    rasp = any(p not in PACKERS for p in protectors)

    # 1. obfuscation
    own = [k for k in classes if an.is_app(k) and not k.startswith(("Landroid", "Ljava", "Lkotlin"))]
    short = sum(1 for k in own if len(k.rsplit("/", 1)[-1].rstrip(";").split("$")[0]) <= 2)
    ratio = short / len(own) if own else 0
    app_named = [k for k in classes if an.app_prefixes and k.lower().startswith(an.app_prefixes)]
    readable = sum(1 for k in app_named if len(k.rsplit("/", 1)[-1].rstrip(";").split("$")[0]) > 2)
    obfuscated = ratio > 0.4 or (app_named and readable / len(app_named) < 0.5) or "Guardsquare DexGuard" in protectors
    if not obfuscated and len(app_named) > 5:
        ex = app_named[0][1:-1].replace("/", ".")
        c.add("AND-NOT-OBFUSCATED", "classes*.dex", 0,
              f"{readable}/{len(app_named)} app classes keep readable names (e.g. {ex})")
    rows.append(_row("Code obfuscation (R8 / ProGuard / DexGuard)", obfuscated or not app_named,
                     f"{short}/{len(own)} classes have short obfuscated names" if obfuscated else "too few app classes to judge",
                     "AND-NOT-OBFUSCATED", "Class and method names are readable in decompiled code"))

    # 2. source file names / line numbers
    srcs = [idx.classes[k][1].source_file for k in app_named]
    real_src = [s for s in srcs if s.endswith((".java", ".kt"))]
    if app_named and len(real_src) / len(app_named) > 0.5:
        c.add("AND-DEBUG-INFO-RETAINED", "classes*.dex", 0,
              f"{len(real_src)}/{len(app_named)} app classes keep their source file name (e.g. {real_src[0]})")
    rows.append(_row("Source file names stripped", not (app_named and len(real_src) / len(app_named) > 0.5),
                     "SourceFile attribute renamed or removed", "AND-DEBUG-INFO-RETAINED",
                     f"{len(real_src)} classes reveal original .java/.kt file names"))

    # 3. root detection, 4. anti-debug, 5. hooking, 6. emulator, 7. tamper, 8. attestation, 9. tapjacking
    def app_used(users):
        return any(an.is_app(m.cls) for _dx, m, *_ in users)

    app_strings = [st for st, users in idx.string_users.items() if len(st) < 200 and app_used(users)]

    def has(rx, extra=()):
        hit = _first(rx, app_strings)
        if hit:
            return f'string "{hit}" used in app code'
        for api in extra:
            if "->" in api:
                users = idx.callers.get(api, []) + idx.field_users.get(api, [])
                if app_used(users):
                    return api.split(";")[0].rsplit("/", 1)[-1] + "." + api.split("->")[1] + "() called from app code"
            elif api in idx.classes:
                return api[1:-1].replace("/", ".") + " bundled"
        return None

    checks = [
        ("Root detection", ROOT_RX, ("Lcom/scottyab/rootbeer/RootBeer;",), "AND-NO-ROOT-DETECTION",
         "No root-detection strings or libraries found"),
        ("Anti-debugging", ANTI_DEBUG_RX, ("Landroid/os/Debug;->isDebuggerConnected", "Landroid/os/Debug;->waitingForDebugger"),
         "AND-NO-ANTI-DEBUG", "No Debug.isDebuggerConnected / TracerPid / adb checks found"),
        ("Hooking / instrumentation detection (Frida, Xposed)", HOOK_RX, (), "AND-NO-HOOK-DETECTION",
         "No Frida / Xposed / Substrate indicators checked"),
        ("Emulator detection", EMU_RX, (), "AND-NO-EMULATOR-DETECTION", "No emulator fingerprints checked"),
        ("Anti-tampering (signature / installer check)", TAMPER_RX,
         ("Landroid/content/pm/PackageInfo;->signatures", "Landroid/content/pm/PackageInfo;->signingInfo",
          "Landroid/content/pm/SigningInfo;->getApkContentsSigners", "Landroid/content/pm/PackageManager;->getInstallerPackageName",
          "Landroid/content/pm/PackageManager;->getInstallSourceInfo"),
         "AND-NO-TAMPER-CHECK", "App never inspects its own signature or installer"),
        ("Integrity attestation (Play Integrity)", ATTEST_RX,
         ("Lcom/google/android/play/core/integrity/IntegrityManager;->requestIntegrityToken",
          "Lcom/google/android/play/core/integrity/StandardIntegrityManager;->prepareIntegrityToken",
          "Lcom/google/android/gms/safetynet/SafetyNetClient;->attest"),
         "AND-NO-ATTESTATION", "Play Integrity / SafetyNet not used"),
        ("Tapjacking / overlay protection", TAPJACK_RX,
         ("Landroid/view/View;->setFilterTouchesWhenObscured", "Landroid/view/Window;->setHideOverlayWindows"),
         "AND-NO-TAPJACKING-PROTECTION", "No filterTouchesWhenObscured / setHideOverlayWindows"),
    ]
    layout_hit = None
    for n in names:
        if n.startswith("res/layout") and n.endswith(".xml"):
            try:
                if "filterTouchesWhenObscured".encode("utf-16-le") in an.z.read(n):
                    layout_hit = n
                    break
            except Exception:
                pass
    emu_ev = None
    for fld in ("FINGERPRINT", "HARDWARE", "PRODUCT", "MODEL", "MANUFACTURER", "BRAND"):
        for dx, m in idx.field_users.get(f"Landroid/os/Build;->{fld}", []):
            if an.is_app(m.cls) and any(re.search(r"(?i)^(generic|unknown|goldfish|ranchu|sdk|google_sdk|emulator|vbox|genymotion)",
                                                  x) for x in idx.method_strings(dx, m)):
                emu_ev = f"Build.{fld} compared with emulator values in {m.cls[1:-1].replace('/', '.')}.{m.name}()"
                break
        if emu_ev:
            break
    for label, rx, apis, rule, msg in checks:
        ev = has(rx, apis)
        if rule == "AND-NO-EMULATOR-DETECTION" and not ev:
            ev = emu_ev
        if rule == "AND-NO-TAPJACKING-PROTECTION" and not ev and layout_hit:
            ev = f"filterTouchesWhenObscured in {layout_hit}"
        if rasp and not ev and rule in ("AND-NO-ROOT-DETECTION", "AND-NO-ANTI-DEBUG", "AND-NO-HOOK-DETECTION",
                                        "AND-NO-EMULATOR-DETECTION", "AND-NO-TAMPER-CHECK"):
            ev = "RASP SDK: " + ", ".join(p for p in protectors if p not in PACKERS)
        if not ev:
            c.add(rule, "classes*.dex", 0, msg)
        rows.append(_row(label, bool(ev), ev, rule, msg))

    # 10. screenshots
    flag_secure = "AND-NO-FLAG-SECURE" not in c.by_rule
    rows.append(_row("Screenshot / screen-recording protection (FLAG_SECURE)", flag_secure, "FLAG_SECURE set", "AND-NO-FLAG-SECURE",
                     "FLAG_SECURE never set"))

    # 11. native libraries stripped (app's own libs only)
    from .parsers import elf
    unstripped = []
    for n in names:
        if n.startswith("lib/") and n.endswith(".so") and not re.search(
                r"lib(c\+\+_shared|flutter|sqlcipher|jsc|hermes|reactnative|realm|crashlytics|sentry|tensorflow|opencv|"
                r"stlport|gnustl|unity|il2cpp|mono|conscrypt|fb|yoga|glog|folly)", n):
            try:
                if not elf.parse(an.z.read(n)).stripped:
                    unstripped.append(n)
            except Exception:
                pass
    if unstripped:
        c.add("AND-NATIVE-NOT-STRIPPED", unstripped[0], 0, f"{len(unstripped)} app .so file(s) keep a symbol table: " +
              ", ".join(u.rsplit("/", 1)[-1] for u in unstripped[:4]))
    if any(n.startswith("lib/") and n.endswith(".so") for n in names):
        rows.append(_row("Native libraries stripped", not unstripped, "no symbol tables in app .so files",
                         "AND-NATIVE-NOT-STRIPPED", f"{len(unstripped)} .so with symbols"))

    # 12. debuggable / logging / pinning (cross-links to existing findings)
    rows.append(_row("Release build not debuggable", "AND-DEBUGGABLE" not in c.by_rule, "android:debuggable not set",
                     "AND-DEBUGGABLE", "android:debuggable=true"))
    rows.append(_row("Certificate pinning", "AND-NO-PINNING" not in c.by_rule, "pin-set / CertificatePinner found",
                     "AND-NO-PINNING", "No pinning configuration found"))

    # 13. plaintext sensitive strings
    secret_findings = [r for r in ("SEC-HARDCODED", "AND-CRYPTO-HARDCODED-KEY") if r in c.by_rule]
    if secret_findings and not protectors:
        c.add("AND-NO-STRING-ENCRYPTION", "classes*.dex", 0,
              "Secrets or keys are readable as plain strings (see " + ", ".join(secret_findings) + ")")
    return {"protectors": protectors, "checklist": rows}


# =============================================================== iOS (IPA)
def ios_ipa(an, mo) -> dict:
    c, imp = an.c, mo.imports
    strings = mo.strings
    haystack = an.names + [s for s in strings if len(s) < 120] + mo.libraries
    protectors = detect_protectors(haystack)
    rasp = bool(protectors)
    rows = []
    loc = an.app_dir + an.exe_name

    # obfuscation: are ObjC / Swift type names human readable?
    names = [s for s in strings if re.fullmatch(r"[A-Z][A-Za-z0-9_]{3,60}", s)]
    wordy = sum(1 for s in names if re.search(r"[aeiou]", s[1:]) and re.search(r"[a-z]{3}", s))
    readable = (wordy / len(names)) if names else 0
    obf = len(names) < 20 or readable < 0.6
    if not obf:
        c.add("IOS-NOT-OBFUSCATED", loc, 0, f"{wordy}/{len(names)} class/type names are readable (e.g. "
              + ", ".join(names[:3]) + ")")
    rows.append(_row("Class / method name obfuscation", obf, "names look obfuscated or minimal", "IOS-NOT-OBFUSCATED",
                     f"{wordy}/{len(names)} type names are readable"))
    rows.append(_row("Debug symbols stripped", "IOS-NOT-STRIPPED" not in c.by_rule, "no local symbols", "IOS-NOT-STRIPPED",
                     f"{mo.local_symbols} local symbols present"))

    def has(rx, syms=()):
        for s in syms:
            if s in imp:
                return f"imports {s}"
        hit = _first(rx, strings)
        return f'string "{hit}"' if hit else None

    checks = [
        ("Jailbreak detection", re.compile(r"(/Applications/Cydia\.app|cydia://|/bin/bash|/usr/sbin/sshd|/etc/apt|"
                                           r"MobileSubstrate|/private/jailbreak|/var/jb|Sileo|isJailbroken|amIJailbroken)", re.I),
         (), "IOS-NO-JB-DETECTION", "No jailbreak-detection indicators"),
        ("Anti-debugging", ANTI_DEBUG_RX, ("_ptrace",), "IOS-NO-ANTI-DEBUG", "No ptrace / sysctl debugger checks"),
        ("Hooking / instrumentation detection (Frida, Substrate)", HOOK_RX, (), "IOS-NO-HOOK-DETECTION",
         "No Frida / Substrate / injected dylib checks"),
        ("Anti-tampering (re-signing / bundle integrity)", TAMPER_RX, (), "IOS-NO-TAMPER-CHECK",
         "No code-signature or provisioning checks"),
        ("Integrity attestation (App Attest / DeviceCheck)", ATTEST_RX,
         ("_OBJC_CLASS_$_DCAppAttestService", "_OBJC_CLASS_$_DCDevice"), "IOS-NO-ATTESTATION", "App Attest not used"),
        ("Screen recording / screenshot protection", SCREEN_IOS_RX, ("_UIScreenCapturedDidChangeNotification",
                                                                     "_UIApplicationUserDidTakeScreenshotNotification"),
         "IOS-NO-SCREEN-PROTECTION", "No reaction to screen capture or screenshots"),
    ]
    for label, rx, syms, rule, msg in checks:
        ev = has(rx, syms)
        if rasp and not ev and rule in ("IOS-NO-JB-DETECTION", "IOS-NO-ANTI-DEBUG", "IOS-NO-HOOK-DETECTION", "IOS-NO-TAMPER-CHECK"):
            ev = "RASP SDK: " + ", ".join(protectors)
        if not ev:
            c.add(rule, loc, 0, msg)
        rows.append(_row(label, bool(ev), ev, rule, msg))
    rows.append(_row("Release build not debuggable (get-task-allow)", "IOS-GET-TASK-ALLOW" not in c.by_rule,
                     "get-task-allow false", "IOS-GET-TASK-ALLOW", "get-task-allow = true"))
    rows.append(_row("Certificate pinning", "IOS-NO-PINNING" not in c.by_rule, "pinning indicators found", "IOS-NO-PINNING",
                     "No pinning indicators"))
    rows.append(_row("PIE / stack canary / ARC", mo.pie and mo.stack_canary and (mo.arc or not mo.uses_objc),
                     "all enabled", "IOS-NO-PIE", "one or more compiler protections missing"))
    return {"protectors": protectors, "checklist": rows}


# =============================================================== source code
def source(scanner, texts: dict, kinds: set, deps: list) -> dict:
    c = scanner.c
    code = {r: t for r, t in texts.items() if r.endswith((".java", ".kt", ".swift", ".m", ".mm", ".dart", ".js", ".ts",
                                                          ".tsx", ".jsx", ".xml", ".plist", ".gradle", ".kts", ".json", ".yaml"))}
    joined = "\n".join(code.values())
    haystack = list(code) + deps + [joined[:0]]
    protectors = detect_protectors(haystack + [l for l in joined.splitlines() if "import" in l or "implementation" in l][:5000])
    rasp = bool(protectors)
    rows = []

    def where(rx):
        for r, t in code.items():
            m = rx.search(t)
            if m:
                return f"{r}:{t.count(chr(10), 0, m.start()) + 1}"
        return None

    # ProGuard / R8 rules
    rules_txt = {r: t for r, t in texts.items() if re.search(r"(proguard|r8)[^/]*\.(pro|txt|cfg)$", r, re.I)}
    if "Android" in kinds:
        for r, t in rules_txt.items():
            m = re.search(r"(?m)^\s*-dontobfuscate", t)
            if m:
                c.add("AND-NOT-OBFUSCATED", r, t.count("\n", 0, m.start()) + 1, "-dontobfuscate")
            if re.search(r"-keepattributes[^\n]*SourceFile", t) and "-renamesourcefileattribute" not in t:
                ln = t.count("\n", 0, t.find("-keepattributes")) + 1
                c.add("AND-DEBUG-INFO-RETAINED", r, ln, "-keepattributes SourceFile without -renamesourcefileattribute")
        rows.append(_row("Code obfuscation (R8 / ProGuard)", "AND-NOT-OBFUSCATED" not in c.by_rule, "minify enabled for release",
                         "AND-NOT-OBFUSCATED", "minifyEnabled false / -dontobfuscate / no release build type"))
        spec = [("Root detection", ROOT_RX, "AND-NO-ROOT-DETECTION"), ("Anti-debugging", ANTI_DEBUG_RX, "AND-NO-ANTI-DEBUG"),
                ("Hooking detection (Frida, Xposed)", HOOK_RX, "AND-NO-HOOK-DETECTION"),
                ("Emulator detection", EMU_RX, "AND-NO-EMULATOR-DETECTION"),
                ("Anti-tampering (signature / installer)", TAMPER_RX, "AND-NO-TAMPER-CHECK"),
                ("Play Integrity attestation", ATTEST_RX, "AND-NO-ATTESTATION"),
                ("Tapjacking protection", TAPJACK_RX, "AND-NO-TAPJACKING-PROTECTION")]
        for label, rx, rule in spec:
            ev = where(rx) or (("RASP: " + ", ".join(protectors)) if rasp and rule not in ("AND-NO-ATTESTATION", "AND-NO-TAPJACKING-PROTECTION") else None)
            if not ev:
                c.add(rule, "(project)", 0, f"{label}: no implementation found")
            rows.append(_row(label, bool(ev), ev, rule, "not found in source"))
        rows.append(_row("Screenshot protection (FLAG_SECURE)", "AND-NO-FLAG-SECURE" not in c.by_rule, "FLAG_SECURE used",
                         "AND-NO-FLAG-SECURE", "FLAG_SECURE never set"))
    if "iOS" in kinds:
        jb = re.compile(r"(Cydia|/bin/bash|/usr/sbin/sshd|isJailbroken|amIJailbroken|/var/jb|IOSSecuritySuite)")
        spec = [("Jailbreak detection", jb, "IOS-NO-JB-DETECTION"), ("Anti-debugging", ANTI_DEBUG_RX, "IOS-NO-ANTI-DEBUG"),
                ("Hooking detection (Frida, Substrate)", HOOK_RX, "IOS-NO-HOOK-DETECTION"),
                ("Anti-tampering (re-signing)", TAMPER_RX, "IOS-NO-TAMPER-CHECK"),
                ("App Attest / DeviceCheck", ATTEST_RX, "IOS-NO-ATTESTATION"),
                ("Screen capture protection", SCREEN_IOS_RX, "IOS-NO-SCREEN-PROTECTION")]
        for label, rx, rule in spec:
            ev = where(rx) or (("RASP: " + ", ".join(protectors)) if rasp and rule not in ("IOS-NO-ATTESTATION", "IOS-NO-SCREEN-PROTECTION") else None)
            if not ev:
                c.add(rule, "(project)", 0, f"{label}: no implementation found")
            rows.append(_row(label, bool(ev), ev, rule, "not found in source"))
        pbx = "\n".join(t for r, t in texts.items() if r.endswith(".pbxproj"))
        if pbx:
            strip_off = re.search(r"STRIP_INSTALLED_PRODUCT\s*=\s*NO", pbx) or re.search(r"DEPLOYMENT_POSTPROCESSING\s*=\s*NO", pbx)
            if strip_off:
                c.add("IOS-NOT-STRIPPED", "project.pbxproj", 0, strip_off.group(0) + " (check the Release configuration)")
            rows.append(_row("Symbols stripped in Release", not strip_off, "default strip settings", "IOS-NOT-STRIPPED",
                             strip_off.group(0) if strip_off else ""))
    return {"protectors": protectors, "checklist": rows}


def apply_profile(findings, profile: str):
    """high-risk profile: missing resilience controls become medium (MASVS-R expectation)."""
    if profile != "high-risk":
        return
    for f in findings:
        if f.rule_id in RESILIENCE_RULES and f.severity in ("info", "low"):
            f.severity = "medium"
            if f.analysis and f.analysis.get("severity") in ("info", "low"):
                f.analysis["severity"] = "medium"
