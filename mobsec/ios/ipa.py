"""IPA analyzer: Info.plist, entitlements, Mach-O protections, imported APIs, strings, bundle files."""
from __future__ import annotations

import hashlib
import io
import json
import plistlib
import re
import zipfile

from .. import secrets as S
from ..finding import Collector, ScanResult
from ..parsers import macho
from .plist_checks import check_entitlements, check_info_plist

URL_IGNORE = re.compile(r"(?i)^http://(www\.w3\.org|www\.apple\.com/DTDs|ns\.adobe\.com|purl\.org|localhost|127\.0\.0\.1|"
                        r"schemas\.|xml\.|www\.example\.com|example\.com/?$|crl\.|ocsp\.|www\.webkit\.org|"
                        r"json-schema\.org|iptc\.org|cipa\.jp)")
SECRET_KEY_NAME = re.compile(r"^(?!set|get|is|has|CBL|NS|UI)[a-z][A-Za-z0-9_.]*(?i:password|passwd|pin|token|secret|credential|session|apikey|api_key|ssn|cvv)[A-Za-z0-9_]*$")
SQL_TAIL = re.compile(r"(?i)\b(select|update|delete|insert)\b.*(=|\blike)\s*['\"]?%?$")
SQL_FMT = re.compile(r"(?i)\b(select\s.+\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b.*"
                     r"(=|\blike|\bvalues\s*\()\s*\(?\s*['\"]?%(@|s|d|i|ld)")
JB_HINTS = re.compile(r"(/Applications/Cydia\.app|cydia://|/bin/bash|/usr/sbin/sshd|/etc/apt|MobileSubstrate|"
                      r"/private/jailbreak|/usr/bin/ssh|Sileo|/var/jb|frida|isJailbroken|IOSSecuritySuite)", re.I)
PIN_HINTS = re.compile(r"(TrustKit|pinnedCertificates|PinnedCertificatesTrustEvaluator|PublicKeysTrustEvaluator|"
                       r"AFSSLPinningMode(Certificate|PublicKey)|SSLPinningMode|NSPinnedDomains|evaluateServerTrust)")
TLS_BYPASS = ["setAllowInvalidCertificates:", "allowInvalidCertificates", "setValidatesDomainName:",
              "allowsAnyHTTPSCertificateForHost:", "setAllowsAnyHTTPSCertificate:forHost:",
              "DisabledTrustEvaluator", "DisabledEvaluator", "kCFStreamSSLValidatesCertificateChain"]
TEXT_EXT = (".json", ".js", ".jsbundle", ".html", ".htm", ".xml", ".txt", ".config", ".cfg", ".yaml", ".yml",
            ".properties", ".env", ".strings", ".graphql", ".plist")
KEY_EXT = (".p12", ".pfx", ".pem", ".key", ".jks", ".keystore")
SOURCE_EXT = (".h", ".m", ".mm", ".swift", ".c", ".cpp", ".xcconfig", ".pch")


def _plist(data: bytes):
    try:
        return plistlib.loads(data)
    except Exception:
        return None


class IPAAnalyzer:
    def __init__(self, path: str, data: bytes | None = None):
        self.path = path
        raw = data if data is not None else open(path, "rb").read()
        self.sha256 = hashlib.sha256(raw).hexdigest()
        self.z = zipfile.ZipFile(io.BytesIO(raw))
        self.names = self.z.namelist()
        self.c = Collector()
        self.notes = []
        apps = sorted({m.group(0) for n in self.names if (m := re.match(r"Payload/[^/]+\.app/", n))})
        if not apps:
            raise ValueError("not an IPA: no Payload/*.app directory")
        self.app_dir = apps[0]

    def run(self) -> ScanResult:
        z, app_dir = self.z, self.app_dir
        info = _plist(z.read(app_dir + "Info.plist")) or {}
        ptext = None
        self.pinning = check_info_plist(info, self.c, app_dir + "Info.plist", ptext)["pinning"]
        exe_name = info.get("CFBundleExecutable") or app_dir.split("/")[1][:-4]
        exe = app_dir + exe_name
        self.exe_name = exe_name
        if exe not in self.names:
            raise ValueError(f"main executable {exe} not found in the IPA")
        try:
            mo = macho.parse(z.read(exe))
        except macho.MachOError as e:
            raise ValueError(f"{exe}: {e}") from None
        self.mo = mo
        ent = mo.entitlements
        if not ent and app_dir + "embedded.mobileprovision" in self.names:
            ent = _provision_entitlements(z.read(app_dir + "embedded.mobileprovision"))
        check_entitlements(ent or {}, self.c, exe + " (code signature)" if mo.entitlements else app_dir + "embedded.mobileprovision")

        self.binary_checks(mo, exe)
        frameworks = self.framework_checks()
        self.bundle_checks()
        from ..hardening import ios_ipa
        hardening = ios_ipa(self, mo)

        if not any(n.endswith("PrivacyInfo.xcprivacy") and n.startswith(app_dir) and n.count("/") == 3 for n in self.names):
            self.c.add("IOS-NO-PRIVACY-MANIFEST", app_dir, 0, "No PrivacyInfo.xcprivacy in the app bundle")
        if mo.encrypted:
            self.notes.append("The main binary is FairPlay-encrypted (App Store download). Strings and API checks are "
                              "incomplete; scan a decrypted or development/ad-hoc IPA for full results.")
        fw_kinds = []
        if any("/Flutter.framework/" in n for n in self.names):
            fw_kinds.append("Flutter")
            self.notes.append("Flutter app: Dart code in App.framework is checked for strings/secrets only.")
        if any(n.endswith("main.jsbundle") for n in self.names):
            fw_kinds.append("React Native")
        if any(n.startswith(app_dir + "www/") for n in self.names):
            fw_kinds.append("Cordova / Ionic")
        if any(i.startswith("_$s") or i.startswith("_swift_") for i in mo.imports):
            fw_kinds.append("Swift")
        if mo.uses_objc:
            fw_kinds.append("Objective-C")

        app = {
            "platform": "iOS", "bundle_id": info.get("CFBundleIdentifier", ""), "name": info.get("CFBundleDisplayName") or info.get("CFBundleName", ""),
            "version": f"{info.get('CFBundleShortVersionString', '')} ({info.get('CFBundleVersion', '')})",
            "min_os": info.get("MinimumOSVersion") or mo.min_os, "sha256": self.sha256,
            "binary": {"arch": mo.arch, "slices": mo.slices, "pie": mo.pie, "stack_canary": mo.stack_canary,
                       "arc": mo.arc, "encrypted": mo.encrypted, "stripped": mo.local_symbols < 1000},
            "entitlements": sorted((ent or {}).keys()),
            "permissions": [k for k in info if k.endswith("UsageDescription")],
            "url_schemes": [s for t in (info.get("CFBundleURLTypes") or []) if isinstance(t, dict) for s in t.get("CFBundleURLSchemes", [])],
            "frameworks": frameworks, "tech": fw_kinds, "linked_libraries": len(mo.libraries),
            "hardening": hardening,
        }
        return ScanResult(self.path, "ipa", app, self.c.results(), len(self.names), self.notes)

    # ------------------------------------------------------------ main binary
    def binary_checks(self, mo: macho.MachO, exe: str):
        c, imp = self.c, mo.imports
        strs = mo.strings
        sset = set(strs)
        loc = exe
        has = lambda *names: [n for n in names if n in imp]
        ctx = lambda syms: "imports: " + ", ".join(sorted(syms)[:40])

        if mo.filetype == 2 and not mo.pie:
            c.add("IOS-NO-PIE", loc, 0, "MH_PIE flag not set")
        if not mo.stack_canary:
            c.add("IOS-NO-CANARY", loc, 0, "___stack_chk_guard / ___stack_chk_fail not imported")
        if mo.uses_objc and not mo.arc:
            c.add("IOS-NO-ARC", loc, 0, "_objc_release not imported")
        if mo.stack_exec:
            c.add("IOS-STACK-EXEC", loc, 0, "MH_ALLOW_STACK_EXECUTION set")
        if mo.local_symbols > 1000:
            c.add("IOS-NOT-STRIPPED", loc, 0, f"{mo.local_symbols} local/debug symbols present")
        if mo.encrypted:
            c.add("IOS-ENCRYPTED", loc, 0, "LC_ENCRYPTION_INFO cryptid = 1")

        weak_hash = has("_CC_MD5", "_CC_MD5_Init", "_CC_SHA1", "_CC_SHA1_Init", "_CC_MD2", "_CC_MD4") + \
            [i for i in imp if "8InsecureO3MD5" in i or "8InsecureO4SHA1" in i][:2]
        if weak_hash:
            c.add("IOS-WEAK-HASH", loc, 0, "Imports " + ", ".join(sorted(weak_hash)[:6]), ctx(weak_hash))
        if "_CCCrypt" in imp or "_CCCryptorCreate" in imp:
            ecb = [s for s in strs if re.search(r"(?i)\b(ECB|kCCOptionECBMode|DES|3DES|RC4)\b", s) and len(s) < 60][:3]
            if ecb:
                c.add("IOS-WEAK-CIPHER", loc, 0, f"CommonCrypto CCCrypt used; strings mention: {ecb}", severity="medium",
                      note="Strings suggest ECB or a legacy cipher; confirm in code.")
        rnd = has("_rand", "_srand", "_random", "_srandom")
        if rnd:
            c.add("IOS-WEAK-RANDOM", loc, 0, "Imports " + ", ".join(rnd))
        unsafe = has("_strcpy", "_strcat", "_sprintf", "_vsprintf", "_gets", "_scanf", "_sscanf", "_strncpy")
        if unsafe:
            c.add("IOS-UNSAFE-C", loc, 0, "Imports " + ", ".join(unsafe))
        logs = has("_NSLog", "_NSLogv") + [i for i in imp if "5print_9separator10terminator" in i][:1]
        if logs:
            c.add("IOS-LOGGING", loc, 0, "Imports " + ", ".join(x if len(x) < 30 else "Swift.print" for x in logs))

        weak_kc = has("_kSecAttrAccessibleAlways", "_kSecAttrAccessibleAlwaysThisDeviceOnly", "_kSecAttrAccessibleAfterFirstUnlock")
        if weak_kc:
            c.add("IOS-KEYCHAIN-WEAK", loc, 0, "Imports " + ", ".join(weak_kc))
        elif "_kSecAttrAccessibleWhenUnlocked" in imp and "_kSecAttrAccessibleWhenUnlockedThisDeviceOnly" not in imp:
            c.add("IOS-KEYCHAIN-WEAK", loc, 0, "kSecAttrAccessibleWhenUnlocked (items migrate to other devices via backups)", severity="low")
        if "_NSFileProtectionNone" in imp:
            c.add("IOS-FILE-PROTECTION-NONE", loc, 0, "Imports _NSFileProtectionNone")

        if "_OBJC_CLASS_$_NSUserDefaults" in imp or any("UserDefaults" in i for i in imp if i.startswith("_$s")):
            keys = sorted({s for s in strs if SECRET_KEY_NAME.match(s) and 3 < len(s) < 40})[:8]
            if keys:
                c.add("IOS-USERDEFAULTS-SECRETS", loc, 0, "UserDefaults used; secret-like key strings: " + ", ".join(keys),
                      note="Confirm whether these keys are written to UserDefaults.")

        if "_OBJC_CLASS_$_UIWebView" in imp:
            c.add("IOS-UIWEBVIEW", loc, 0, "References UIWebView class")
        bridge = [s for s in ("addScriptMessageHandler:name:", "addScriptMessageHandler:contentWorld:name:",
                              "allowFileAccessFromFileURLs", "allowUniversalAccessFromFileURLs") if s in sset]
        if bridge:
            c.add("IOS-WKWEBVIEW-BRIDGE", loc, 0, "Uses " + ", ".join(bridge),
                  severity="high" if "allowUniversalAccessFromFileURLs" in bridge else None)

        bypass = [s for s in TLS_BYPASS if s in sset]
        if bypass:
            c.add("IOS-TLS-BYPASS", loc, 0, "References " + ", ".join(bypass), note="Check whether these are set to insecure values.")
        challenge = any("didReceiveChallenge" in s or "didReceiveAuthenticationChallenge" in s for s in strs)
        evaluates = bool(has("_SecTrustEvaluateWithError", "_SecTrustEvaluate", "_SecTrustEvaluateAsyncWithError"))
        if challenge and ("credentialForTrust:" in sset or "useCredential:forAuthenticationChallenge:" in sset) and not evaluates:
            c.add("IOS-TLS-BYPASS", loc, 0, "Implements an authentication-challenge handler that builds a credential from the "
                  "server trust but never calls SecTrustEvaluate*", severity="high")
        net = "_OBJC_CLASS_$_NSURLSession" in imp or any(s.startswith("https://") for s in strs)
        pins = self.pinning or any(PIN_HINTS.search(s) for s in strs) or bool(has("_SecTrustCopyKey", "_SecCertificateCopyData", "_SecTrustCopyPublicKey"))
        if net and not pins:
            c.add("IOS-NO-PINNING", loc, 0, "Networking found but no pinning indicators")

        for s in strs:
            if s.startswith("http://") and len(s) > 10 and not URL_IGNORE.match(s):
                c.add("IOS-HTTP-URL", loc, 0, s[:150])

        if "_OBJC_CLASS_$_LAContext" in imp and "evaluatePolicy:localizedReason:reply:" in sset \
                and "_SecAccessControlCreateWithFlags" not in imp:
            c.add("IOS-BIOMETRIC-EVENT", loc, 0, "LAContext evaluatePolicy used and SecAccessControlCreateWithFlags is not imported")
        if "_OBJC_CLASS_$_UIPasteboard" in imp:
            c.add("IOS-PASTEBOARD", loc, 0, "References UIPasteboard")
        if has("_sqlite3_exec", "_sqlite3_prepare_v2", "_sqlite3_prepare"):
            for s in strs:
                if SQL_FMT.search(s) or SQL_TAIL.search(s.rstrip()):
                    c.add("IOS-SQLI", loc, 0, f'SQL format string: "{s[:120]}"')
        db = has("_sqlite3_open", "_sqlite3_open_v2") + (["Realm"] if any("RLMRealm" in s or "RealmSwift" in s for s in mo.libraries + strs[:0]) or
                                                          "_OBJC_CLASS_$_RLMRealm" in imp else []) + \
            (["CoreData"] if "_OBJC_CLASS_$_NSPersistentContainer" in imp or "_OBJC_CLASS_$_NSManagedObjectContext" in imp else [])
        if db and "_sqlite3_key" not in imp and "setEncryptionKey:" not in sset and "encryptionKey" not in sset:
            c.add("IOS-DB-PLAIN", loc, 0, "Local database APIs: " + ", ".join(db))

        for s in strs:
            if len(s) < 16:
                continue
            for kind, val, sev, _ in S.scan_text(s, assignments=False):
                c.add("SEC-HARDCODED", loc, 0, f"{kind}: {S.mask(val)}", severity=sev if sev != "info" else "low")
            if S.FIREBASE.search(s):
                c.add("SEC-FIREBASE", loc, 0, S.FIREBASE.search(s).group(0))
            if S.BUCKET.search(s):
                c.add("SEC-CLOUD-BUCKET", loc, 0, S.BUCKET.search(s).group(0)[:120])

    # ------------------------------------------------------------ embedded frameworks
    def framework_checks(self):
        out = []
        fw_bins = {}
        for n in self.names:
            m = re.match(re.escape(self.app_dir) + r"Frameworks/([^/]+)\.framework/([^/]+)$", n)
            if m and m.group(1) == m.group(2):
                fw_bins[m.group(1)] = n
            elif re.match(re.escape(self.app_dir) + r"Frameworks/[^/]+\.dylib$", n) and "libswift" not in n:
                fw_bins[n.rsplit("/", 1)[-1]] = n
        for name, path in sorted(fw_bins.items()):
            out.append(name)
            try:
                mo = macho.parse(self.z.read(path))
            except Exception:
                continue
            for s in mo.strings:
                if len(s) < 16:
                    continue
                for kind, val, sev, _ in S.scan_text(s, assignments=False):
                    self.c.add("SEC-HARDCODED", path, 0, f"{kind}: {S.mask(val)}", third_party=name not in ("App",),
                               severity=sev if sev != "info" else "low")
            if "_OBJC_CLASS_$_UIWebView" in mo.imports:
                self.c.add("IOS-UIWEBVIEW", path, 0, f"{name} references UIWebView", third_party=True)
            if not mo.stack_canary and mo.imports:
                self.c.add("IOS-NO-CANARY", path, 0, f"{name}: no stack canary", third_party=True)
        if out:
            self.c.add("IOS-SDKS", self.app_dir + "Frameworks/", 0, ", ".join(out))
        return out

    # ------------------------------------------------------------ bundle resources
    def bundle_checks(self):
        headers = []
        for n in self.names:
            if not n.startswith(self.app_dir) or n.endswith("/"):
                continue
            low = n.lower()
            info = self.z.getinfo(n)
            if low.endswith(KEY_EXT):
                data = self.z.read(n)
                if low.endswith((".p12", ".pfx", ".jks", ".keystore", ".key")) or b"PRIVATE KEY" in data:
                    self.c.add("SEC-PRIVATE-KEY", n, 0, f"Key container bundled ({info.file_size} bytes)")
                continue
            if low.endswith(SOURCE_EXT):
                headers.append(n[len(self.app_dir):])
                continue
            if low.endswith((".sqlite", ".db", ".realm", ".sqlite3")):
                self.c.add("IOS-DB-PLAIN", n, 0, "Database file shipped in the bundle (readable by anyone with the IPA)")
                continue
            if not low.endswith(TEXT_EXT) or info.file_size > 15_000_000 or "/_codesignature/" in low:
                continue
            data = self.z.read(n)
            if low.endswith(".plist") or low.endswith(".strings"):
                pl = _plist(data)
                if pl is None:
                    continue
                text = json.dumps(pl, indent=1, default=str)
                if low.endswith("googleservice-info.plist"):
                    if isinstance(pl, dict) and pl.get("DATABASE_URL"):
                        self.c.add("SEC-FIREBASE", n, 0, str(pl["DATABASE_URL"]))
                    continue  # client keys designed to ship; restricted in console
            else:
                text = data.decode("utf-8", "ignore")
            for kind, val, sev, off in S.scan_text(text):
                self.c.add("SEC-HARDCODED", n, text.count("\n", 0, off) + 1, f"{kind}: {S.mask(val)}",
                           severity=sev if sev != "info" else "low")
            for rx, rule in ((S.FIREBASE, "SEC-FIREBASE"), (S.BUCKET, "SEC-CLOUD-BUCKET")):
                mm = rx.search(text)
                if mm:
                    self.c.add(rule, n, text.count("\n", 0, mm.start()) + 1, mm.group(0)[:120])
            if low.endswith((".js", ".jsbundle", ".html", ".json")):
                for mm in re.finditer(r"[\"'](http://[^\"'\s]{6,})[\"']", text):
                    if not URL_IGNORE.match(mm.group(1)):
                        self.c.add("IOS-HTTP-URL", n, text.count("\n", 0, mm.start()) + 1, mm.group(1)[:150])
        if headers:
            self.c.add("IOS-BUNDLED-HEADERS", self.app_dir, 0, ", ".join(headers[:10]) + (" ..." if len(headers) > 10 else ""))


def _provision_entitlements(data: bytes) -> dict:
    s, e = data.find(b"<?xml"), data.find(b"</plist>")
    if s < 0 or e < 0:
        return {}
    try:
        return plistlib.loads(data[s:e + 8]).get("Entitlements", {})
    except Exception:
        return {}


def analyze(path: str) -> ScanResult:
    return IPAAnalyzer(path).run()
