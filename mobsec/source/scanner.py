"""Source-code scanner for Android, iOS and cross-platform (Flutter / React Native) projects."""
from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import tempfile
import zipfile
from pathlib import Path

from .. import secrets as S
from ..android.manifest import check_manifest, check_nsc, load_text_xml
from ..finding import Collector, ScanResult
from ..ios.plist_checks import check_entitlements, check_info_plist
from .rules import ALL

SKIP_DIRS = {".git", ".svn", ".hg", ".gradle", ".idea", ".vscode", "build", "Build", "DerivedData", "Pods", "Carthage",
             "node_modules", ".build", "SourcePackages", "xcuserdata", ".dart_tool", ".pub-cache", "intermediates",
             "generated", ".cxx", ".externalNativeBuild", "vendor", "__pycache__", ".expo", "dist", "coverage",
             ".next", "web-build"}
TEST_DIRS = {"test", "tests", "androidTest", "testDebug", "Tests", "UITests", "__tests__", "integration_test",
             "sharedTest", "testFixtures"}
CODE_EXT = (".java", ".kt", ".kts", ".gradle", ".swift", ".m", ".mm", ".h", ".dart", ".js", ".jsx", ".ts", ".tsx")
CONFIG_EXT = (".xml", ".plist", ".entitlements", ".json", ".properties", ".xcconfig", ".yaml", ".yml", ".env",
              ".strings", ".pbxproj", ".cfg", ".conf", ".ini")
KEY_EXT = (".p12", ".pfx", ".jks", ".bks", ".keystore", ".pem", ".key")
MAX_BYTES = 3_000_000
VENDOR_RX = re.compile(r"(?i)(^|/)(vendor|vendors|third[_-]?party|external|libs?/[^/]+/src|sdk|frameworks?)/")
CONTEXT = 6

PIN_RX = re.compile(r"CertificatePinner|<pin-set|TrustKit|NSPinnedDomains|pinnedCertificates|PinnedCertificatesTrustEvaluator|"
                    r"PublicKeysTrustEvaluator|SecTrustCopyKey|ssl_pinning|react-native-ssl-pinning|http_certificate_pinning|"
                    r"AFSSLPinningMode(Certificate|PublicKey)")
NET_RX = re.compile(r"OkHttpClient|HttpURLConnection|Retrofit|URLSession|Alamofire|fetch\(|axios|http\.(get|post)|Dio\(")
ROOT_RX = re.compile(r"(?i)RootBeer|isDeviceRooted|isRooted|PlayIntegrity|IntegrityManager|SafetyNet|/system/xbin/su|"
                     r"Cydia|isJailbroken|IOSSecuritySuite|DCAppAttestService|jail_monkey|flutter_jailbreak_detection|freerasp")
FLAG_SECURE_RX = re.compile(r"FLAG_SECURE")


class SourceScanner:
    def __init__(self, path: str, include_tests: bool = False):
        self.path = path
        self.include_tests = include_tests
        self.c = Collector()
        self.notes = []
        self.tmp = None
        p = Path(path).expanduser().resolve()
        if p.is_file() and p.suffix.lower() == ".zip":
            self.tmp = Path(tempfile.mkdtemp(prefix="mobsec_src_"))
            with zipfile.ZipFile(p) as z:
                for m in z.infolist():
                    dest = (self.tmp / m.filename).resolve()
                    if str(dest).startswith(str(self.tmp)):  # zip-slip guard
                        z.extract(m, self.tmp)
            p = self.tmp
        if not p.is_dir():
            raise ValueError(f"{path} is not a directory or .zip of source code")
        self.root = p

    def files(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.endswith((".xcassets", ".lproj"))
                           and (self.include_tests or d not in TEST_DIRS)]
            for n in filenames:
                yield Path(dirpath) / n

    def rel(self, p: Path) -> str:
        return str(p.relative_to(self.root)).replace(os.sep, "/")

    def run(self) -> ScanResult:
        try:
            return self._run()
        finally:
            if self.tmp:
                shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self) -> ScanResult:
        texts: dict[str, str] = {}
        kinds = set()
        scanned = 0
        manifests, gradle_files, plists, ents = [], [], [], []
        key_files, privacy_manifest = [], False
        for f in self.files():
            name, low = f.name, f.name.lower()
            rel = self.rel(f)
            if low.endswith(KEY_EXT):
                key_files.append(rel)
                continue
            if name == "PrivacyInfo.xcprivacy":
                privacy_manifest = True
            if not low.endswith(CODE_EXT + CONFIG_EXT) and name not in ("Podfile", "Podfile.lock", ".env"):
                continue
            try:
                if f.stat().st_size > MAX_BYTES:
                    continue
                text = f.read_text(errors="ignore")
            except OSError:
                continue
            scanned += 1
            texts[rel] = text
            if name == "AndroidManifest.xml":
                manifests.append(rel)
            elif low.endswith((".gradle", ".gradle.kts")):
                gradle_files.append(rel)
            elif name == "Info.plist" or (low.endswith(".plist") and "CFBundleIdentifier" in text):
                plists.append(rel)
            elif low.endswith(".entitlements"):
                ents.append(rel)
            if low.endswith((".java", ".kt")) or name == "AndroidManifest.xml":
                kinds.add("Android")
            elif low.endswith((".swift", ".m", ".mm")) or low.endswith(".pbxproj"):
                kinds.add("iOS")
            elif low.endswith(".dart"):
                kinds.add("Flutter")
            elif name == "package.json" and "react-native" in text:
                kinds.add("React Native")

        sdk = self.gradle_checks(gradle_files, texts)
        pkgs = []
        for m in manifests:
            try:
                root = load_text_xml(texts[m])
            except Exception as e:
                self.notes.append(f"Could not parse {m}: {e}")
                continue
            mi = check_manifest(root, self.c, m, texts[m], sdk_override=sdk)
            if mi.package:
                pkgs.append(mi.package)
        nsc_pin = False
        for rel, text in texts.items():
            if rel.endswith(".xml") and "<network-security-config" in text:
                try:
                    nsc_pin |= check_nsc(load_text_xml(text), self.c, rel, text)["pinning"]
                except Exception:
                    pass
        for p in plists:
            pl = _load_plist(texts[p], self.root / p)
            if isinstance(pl, dict):
                check_info_plist(pl, self.c, p, texts[p])
        for e in ents:
            pl = _load_plist(texts[e], self.root / e)
            if isinstance(pl, dict):
                check_entitlements(pl, self.c, e, texts[e])
        for k in key_files:
            if not k.lower().endswith(".pem") or "PRIVATE KEY" in (self.root / k).read_text(errors="ignore"):
                self.c.add("SEC-PRIVATE-KEY", k, 0, "Key / keystore file committed in the source tree",
                           severity="medium" if "debug" in k.lower() else None)

        for rel, text in texts.items():
            self.scan_file(rel, text)

        joined_code = "\n".join(t for r, t in texts.items() if r.endswith(CODE_EXT + (".xml", ".plist")))
        if NET_RX.search(joined_code) and not PIN_RX.search(joined_code) and not nsc_pin:
            if "Android" in kinds:
                self.c.add("AND-NO-PINNING", "(project)", 0, "No CertificatePinner, <pin-set> or pinning library found")
            if "iOS" in kinds:
                self.c.add("IOS-NO-PINNING", "(project)", 0, "No NSPinnedDomains, TrustKit or trust evaluation code found")
        if not ROOT_RX.search(joined_code):
            if "Android" in kinds:
                self.c.add("AND-NO-ROOT-DETECTION", "(project)", 0, "No root detection or Play Integrity usage found")
            if "iOS" in kinds:
                self.c.add("IOS-NO-JB-DETECTION", "(project)", 0, "No jailbreak detection or App Attest usage found")
        if "Android" in kinds and manifests and not FLAG_SECURE_RX.search(joined_code):
            self.c.add("AND-NO-FLAG-SECURE", "(project)", 0, "FLAG_SECURE is never set")
        if "iOS" in kinds and not privacy_manifest:
            self.c.add("IOS-NO-PRIVACY-MANIFEST", "(project)", 0, "No PrivacyInfo.xcprivacy in the project")

        deps = self.dependencies(texts)
        app = {"platform": " + ".join(sorted(kinds)) or "unknown", "packages": sorted(set(pkgs)),
               "min_sdk": sdk.get("min"), "target_sdk": sdk.get("target"), "files_scanned": scanned,
               "dependencies": deps[:200]}
        kind = "ios-source" if kinds == {"iOS"} else "android-source" if kinds <= {"Android"} and kinds else "source"
        if not kinds:
            self.notes.append("No Android or iOS project files detected; only generic secret checks were applied.")
        return ScanResult(self.path, kind, app, self.c.results(max_evidence=200), scanned, self.notes)

    # ------------------------------------------------------------ per-file rules
    def scan_file(self, rel: str, text: str):
        low = rel.lower()
        lines = text.splitlines()
        is_code = low.endswith(CODE_EXT)
        for rule in ALL:
            if not low.endswith(rule["exts"]):
                continue
            if rule["requires"] and not re.search(rule["requires"], text):
                continue
            if rule["unless"] and re.search(rule["unless"], text):
                continue
            flags = re.S if rule["multiline"] else 0
            for pat in rule["patterns"]:
                for m in re.finditer(pat, text, flags):
                    ln = text.count("\n", 0, m.start()) + 1
                    src = lines[ln - 1] if ln - 1 < len(lines) else m.group(0)
                    stripped = src.lstrip()
                    if stripped.startswith(("//", "*", "/*", "#")) and is_code:
                        continue
                    if rule["line_unless"] and re.search(rule["line_unless"], src):
                        continue
                    self.c.add(rule["rule"], rel, ln, src.strip(), _ctx(lines, ln), severity=rule["severity"],
                               third_party=bool(VENDOR_RX.search(rel)))
        # secrets in every text file
        if low.endswith(("google-services.json", "googleservice-info.plist")):
            mm = S.FIREBASE.search(text)
            if mm:
                self.c.add("SEC-FIREBASE", rel, text.count("\n", 0, mm.start()) + 1, mm.group(0))
            return
        for kind, val, sev, off in S.scan_text(text, assignments=not low.endswith((".pbxproj", ".strings"))):
            ln = text.count("\n", 0, off) + 1
            src = lines[ln - 1] if ln - 1 < len(lines) else ""
            if src.lstrip().startswith(("//", "#", "*")) and is_code:
                continue
            self.c.add("SEC-HARDCODED", rel, ln, src.strip().replace(val, S.mask(val)), _ctx(lines, ln, val),
                       severity=sev if sev != "info" else "low", third_party=bool(VENDOR_RX.search(rel)))
        for rx, rule in ((S.FIREBASE, "SEC-FIREBASE"), (S.BUCKET, "SEC-CLOUD-BUCKET")):
            for mm in rx.finditer(text):
                ln = text.count("\n", 0, mm.start()) + 1
                self.c.add(rule, rel, ln, mm.group(0)[:150])
                break
        if "PRIVATE KEY-----" in text and not low.endswith(".md"):
            ln = text.count("\n", 0, text.find("PRIVATE KEY-----")) + 1
            self.c.add("SEC-PRIVATE-KEY", rel, ln, "PEM private key embedded in file")

    # ------------------------------------------------------------ gradle
    def gradle_checks(self, files, texts) -> dict:
        sdk = {}
        for g in files:
            t = texts[g]
            for key, rx in (("min", r"minSdk(?:Version)?\s*[=(]?\s*(\d+)"), ("target", r"targetSdk(?:Version)?\s*[=(]?\s*(\d+)")):
                m = re.search(rx, t)
                if m:
                    sdk[key] = min(sdk.get(key, 99), int(m.group(1))) if key == "min" else int(m.group(1))
            m = re.search(r"(applicationId|namespace)\s*=?\s*[\"']([\w.]+)[\"']", t)
            if m:
                sdk.setdefault("package", m.group(2))
            rel_block = _block(t, "release")
            if rel_block is not None:
                body, off = rel_block
                for rx in (r"\bminifyEnabled\s*(=\s*)?false", r"\bisMinifyEnabled\s*=\s*false"):
                    mm = re.search(rx, body)
                    if mm:
                        self.c.add("AND-NOT-OBFUSCATED", g, t.count("\n", 0, off + mm.start()) + 1, mm.group(0))
                for rx in (r"\bdebuggable\s*(=\s*)?true", r"\bisDebuggable\s*=\s*true"):
                    mm = re.search(rx, body)
                    if mm:
                        self.c.add("AND-DEBUGGABLE", g, t.count("\n", 0, off + mm.start()) + 1, mm.group(0) + " (release build type)")
            elif re.search(r"\bandroid\s*\{", t) and "buildTypes" not in t and "com.android.application" in t:
                self.c.add("AND-NOT-OBFUSCATED", g, 0, "No release buildType: R8 minification is off by default")
        return sdk

    def dependencies(self, texts) -> list[str]:
        deps = []
        for rel, t in texts.items():
            if rel.endswith((".gradle", ".gradle.kts")):
                deps += re.findall(r"(?:implementation|api|compile)\s*\(?\s*[\"']([\w.\-]+:[\w.\-]+:[\w.\-+]+)[\"']", t)
            elif rel.endswith("Podfile.lock"):
                deps += re.findall(r"^  - ([\w\-/+]+ \([\d.]+\))", t, re.M)
            elif rel.endswith("Package.resolved"):
                try:
                    d = json.loads(t)
                    pins = d.get("pins") or d.get("object", {}).get("pins", [])
                    deps += [f"{p.get('identity') or p.get('package')} {p.get('state', {}).get('version')}" for p in pins]
                except Exception:
                    pass
            elif rel.endswith("pubspec.yaml"):
                m = re.search(r"^dependencies:\n((?:[ \t]+.*\n)+)", t, re.M)
                if m:
                    deps += [x.strip() for x in m.group(1).splitlines() if ":" in x and not x.strip().startswith("#")][:60]
            elif rel.endswith("package.json") and "/node_modules/" not in rel:
                try:
                    deps += [f"{k}@{v}" for k, v in json.loads(t).get("dependencies", {}).items()]
                except Exception:
                    pass
        return sorted(set(deps))


def _block(text: str, name: str):
    """Return (body, offset) of the first `name { ... }` block (brace-balanced)."""
    m = re.search(r"\b(?:getByName\(\s*\"" + name + r"\"\s*\)|" + name + r")\s*\{", text)
    if not m:
        return None
    i, depth = m.end(), 1
    while i < len(text) and depth:
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        i += 1
    return text[m.end():i - 1], m.end()


def _ctx(lines, ln, mask_value=None):
    lo, hi = max(0, ln - 1 - CONTEXT), min(len(lines), ln + CONTEXT)
    out = "\n".join(f"{i + 1:>5}  {lines[i]}" for i in range(lo, hi))
    return out.replace(mask_value, S.mask(mask_value)) if mask_value else out


def _load_plist(text: str, path: Path):
    try:
        return plistlib.loads(text.encode())
    except Exception:
        try:
            return plistlib.loads(path.read_bytes())
        except Exception:
            return None


def scan(path: str, include_tests: bool = False) -> ScanResult:
    return SourceScanner(path, include_tests).run()
