"""APK analyzer: manifest, network config, DEX bytecode, native libs, signing, secrets."""
from __future__ import annotations

import hashlib
import io
import re
import zipfile
from collections import Counter

from ..finding import Collector, ScanResult
from ..parsers import arsc, axml, elf
from ..parsers.dex import Dex, DexIndex, pretty
from .. import secrets as S
from .manifest import check_manifest, check_nsc

LIB_PREFIXES = (
    "Landroid/", "Landroidx/", "Lcom/google/", "Lkotlin", "Lkotlinx/", "Lokhttp3/", "Lokio/", "Lretrofit2/",
    "Lcom/squareup/", "Lio/reactivex/", "Lrx/", "Lcom/facebook/", "Lorg/apache/", "Ljavax/", "Ljava/",
    "Lcom/fasterxml/", "Lcom/bumptech/", "Lorg/json/", "Lcom/crashlytics/", "Lio/fabric/", "Lcom/firebase/",
    "Lnet/sqlcipher/", "Lorg/bouncycastle/", "Lorg/spongycastle/", "Ldagger/", "Lcom/airbnb/", "Lio/flutter/",
    "Lcom/microsoft/", "Lcom/amazon/", "Lcom/amazonaws/", "Lorg/jetbrains/", "Lorg/intellij/", "Lcom/android/volley/",
    "Lcom/journeyapps/", "Lcom/scottyab/", "Lcom/appsflyer/", "Lcom/adjust/", "Lio/branch/", "Lcom/mixpanel/",
    "Lcom/onesignal/", "Lcom/amplitude/", "Lcom/segment/", "Lcom/braintreepayments/", "Lcom/stripe/",
    "Lcom/paypal/", "Lcom/razorpay/", "Lcom/tozny/", "Lorg/greenrobot/", "Lcom/jakewharton/", "Lbutterknife/",
    "Lcom/nostra13/", "Lcom/github/", "Lorg/slf4j/", "Lch/qos/", "Lcom/yalantis/", "Lio/realm/", "Lcom/couchbase/",
    "Lcom/sun/", "Lsun/", "Ldalvik/", "Lorg/xmlpull/", "Lorg/w3c/", "Lorg/xml/", "Lcom/ibm/", "Lcom/salesforce/",
    "Lcom/unity3d/", "Lcom/applovin/", "Lcom/ironsource/", "Lcom/inmobi/", "Lcom/mopub/", "Lcom/chartboost/",
    "Lcom/startapp/", "Lcom/tencent/", "Lcom/huawei/", "Lcom/sentry/", "Lio/sentry/", "Lcom/bugsnag/",
    "Lcom/newrelic/", "Lcom/datadog/", "Lcom/instabug/", "Lcom/zendesk/", "Lcom/intercom/", "Lio/intercom/",
)

TRACKERS = {
    "Lcom/google/firebase/analytics/": "Firebase Analytics", "Lcom/google/android/gms/ads/": "Google AdMob",
    "Lcom/facebook/appevents/": "Facebook App Events", "Lcom/facebook/ads/": "Facebook Audience Network",
    "Lcom/appsflyer/": "AppsFlyer", "Lcom/adjust/sdk/": "Adjust", "Lio/branch/": "Branch",
    "Lcom/mixpanel/": "Mixpanel", "Lcom/amplitude/": "Amplitude", "Lcom/segment/": "Segment",
    "Lcom/onesignal/": "OneSignal", "Lcom/crashlytics/": "Crashlytics", "Lcom/google/firebase/crashlytics/": "Crashlytics",
    "Lcom/flurry/": "Flurry", "Lcom/clevertap/": "CleverTap", "Lcom/moengage/": "MoEngage", "Lcom/braze/": "Braze",
    "Lcom/appboy/": "Braze", "Lcom/unity3d/ads/": "Unity Ads", "Lcom/applovin/": "AppLovin",
    "Lcom/ironsource/": "ironSource", "Lcom/inmobi/": "InMobi", "Lcom/mopub/": "MoPub", "Lcom/newrelic/": "New Relic",
    "Lio/sentry/": "Sentry", "Lcom/bugsnag/": "Bugsnag", "Lcom/instabug/": "Instabug", "Lcom/heapanalytics/": "Heap",
    "Lcom/uxcam/": "UXCam", "Lcom/smartlook/": "Smartlook", "Lcom/microsoft/clarity/": "Microsoft Clarity",
}

CIPHER_RX = re.compile(r"^(AES|DES|DESede|TripleDES|RC4|ARCFOUR|Blowfish|RC2|RSA|ChaCha20)(/[\w-]+/[\w-]+)?$", re.I)
SQL_RX = re.compile(r"(?i)\b(select\s.+\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from|where\s)")
SECRET_WORDS = re.compile(r"(?i)(password|passwd|pwd|token|secret|credential|pin\b|otp|cvv|card ?number|ssn|session)")
URL_IGNORE = re.compile(r"(?i)^http://(schemas\.android\.com|www\.w3\.org|ns\.adobe\.com|www\.apache\.org|xml\.org|"
                        r"json-schema\.org|purl\.org|xmlpull\.org|java\.sun\.com|www\.google\.com/?$|"
                        r"localhost|127\.0\.0\.1|10\.0\.2\.2|schemas\.xmlsoap\.org|www\.example\.com|example\.com|"
                        r"www\.slf4j\.org|xml\.apache\.org|ns\.|schemas\.)")
ROOT_HINTS = re.compile(r"(/system/xbin/su|/system/bin/su|Superuser\.apk|com\.topjohnwu\.magisk|eu\.chainfire\.supersu|"
                        r"test-keys|com\.noshufou\.android\.su|RootBeer|isDeviceRooted|isRooted)")
TEXT_EXT = (".json", ".js", ".xml", ".properties", ".txt", ".html", ".htm", ".cfg", ".conf", ".ini", ".yaml",
            ".yml", ".plist", ".env", ".config", ".bundle", ".csv", ".graphql")
KEY_EXT = (".p12", ".pfx", ".jks", ".bks", ".keystore", ".pem", ".key", ".der", ".pkcs12")


_MSG_RX = re.compile(r"(?i)(error|exception|failed|invalid|unable|cannot|must |does not|should|null|"
                     r"length|expected|not supported|%[sd])|[.!:?]$")
_NOT_KEY = {"UTF-8", "UTF8", "US-ASCII", "ISO-8859-1", "HMACSHA256", "HMACSHA1", "HMACSHA512", "PBKDF2WITHHMACSHA1",
            "PBKDF2WITHHMACSHA256", "SHA-256", "SHA-1", "MD5", "ANDROIDKEYSTORE", "ANDROIDOPENSSL", "BC", "SC"}


def _key_like(s: str) -> bool:
    return (6 <= len(s) <= 80 and not CIPHER_RX.match(s) and s.upper() not in _NOT_KEY
            and not _MSG_RX.search(s) and not s.startswith(("http", "/", "android.", "com.", "java")))


class APKAnalyzer:
    def __init__(self, path: str, data: bytes | None = None):
        self.path = path
        raw = data if data is not None else open(path, "rb").read()
        self.sha256 = hashlib.sha256(raw).hexdigest()
        z = zipfile.ZipFile(io.BytesIO(raw))
        self.notes = []
        if "AndroidManifest.xml" not in z.namelist():  # .apks / .xapk bundle
            inner = [n for n in z.namelist() if n.endswith(".apk")]
            base = next((n for n in inner if n.rsplit("/", 1)[-1] in ("base.apk", "base-master.apk")), inner[0] if inner else None)
            if not base:
                raise ValueError("not an APK: AndroidManifest.xml missing")
            self.notes.append(f"Bundle detected; analysed {base} (split APKs are not merged).")
            raw = z.read(base)
            z = zipfile.ZipFile(io.BytesIO(raw))
        self.raw, self.z = raw, z
        self.names = z.namelist()
        self.c = Collector()

    # ------------------------------------------------------------ helpers
    def _app_prefixes(self):
        """Package prefixes that belong to the app: manifest package + packages of declared components."""
        prefixes = set()
        if self.pkg:
            prefixes.add("l" + self.pkg.lower().replace(".", "/") + "/")
        names = [self.mi.app.get("android:name", "")] if self.mi.app is not None else []
        names += [n for _t, n, _p in self.mi.exported]
        if self.mi.app is not None:
            names += [el.get("android:name", "") for el in self.mi.app if el.tag in ("activity", "service", "receiver", "provider")]
        for n in names:
            if not n or n.startswith("."):
                continue
            parts = n.split(".")[:-1][:3]
            if len(parts) >= 2:
                p = "L" + "/".join(parts) + "/"
                if not p.startswith(LIB_PREFIXES):
                    prefixes.add(p.lower())
        return tuple(prefixes)

    def is_app(self, cls: str) -> bool:
        low = cls.lower()
        if self.app_prefixes and low.startswith(self.app_prefixes):
            return True
        if cls.startswith(LIB_PREFIXES):
            return False
        # unknown package: app code if the app looks obfuscated, otherwise an unlisted library
        return self.app_class_count < 20

    def ev(self, rule, dx, m, snippet, severity=None, note=""):
        calls = sorted({c.split("->")[0].rsplit("/", 1)[-1].rstrip(";") + "." + c.split("->")[1]
                        for c in self.idx.method_calls(dx, m)})[:30]
        strs = [s for s in self.idx.method_strings(dx, m) if len(s) < 200][:20]
        ctx = f"method: {pretty(m)}{m.proto}\ncalls: {', '.join(calls)}\nstrings: {strs}"
        self.c.add(rule, pretty(m), 0, snippet, ctx, third_party=not self.is_app(m.cls), severity=severity, note=note)

    def calls(self, api, proto=None):
        return self.idx.calls_to(api, proto)

    # ------------------------------------------------------------ main
    def run(self) -> ScanResult:
        z = self.z
        try:
            man = axml.parse(z.read("AndroidManifest.xml"))
        except axml.AXMLError as e:
            raise ValueError(f"AndroidManifest.xml could not be parsed ({e}); is this a valid APK?") from None
        self.mi = check_manifest(man, self.c, "AndroidManifest.xml")
        self.pkg = self.mi.package
        self.pkg_path = "L" + self.pkg.replace(".", "/") + "/" if self.pkg else ""

        self.pinning = False
        for n in self.names:
            if n.startswith("res/") and n.endswith(".xml") and z.getinfo(n).file_size < 60_000:
                try:
                    root = axml.parse(z.read(n))
                except Exception:
                    continue
                if root.tag == "network-security-config":
                    info = check_nsc(root, self.c, n)
                    self.pinning |= info["pinning"]
                    self.nsc_file = n

        dexes = []
        for n in sorted(self.names):
            if re.fullmatch(r"(classes\d*\.dex|assets/.*\.dex)", n):
                try:
                    dexes.append(Dex(z.read(n), n))
                except Exception as e:
                    self.notes.append(f"Could not parse {n}: {e}")
        self.idx = DexIndex(dexes)
        self.app_prefixes = self._app_prefixes()
        self.app_class_count = sum(1 for k in self.idx.classes if k.lower().startswith(self.app_prefixes)) if self.app_prefixes else 0
        self.code_checks()
        self.native_checks()
        self.signing_checks()
        self.secret_checks()

        app_classes = [k for k in self.idx.classes if self.pkg_path and k.startswith(self.pkg_path)]
        frameworks = self.detect_frameworks()
        trackers = sorted({v for k, v in TRACKERS.items() for cls in self._class_prefix_sample(k)})
        if trackers:
            self.c.add("AND-TRACKERS", "classes*.dex", 0, ", ".join(trackers), third_party=False)
        sig = self.signature_info
        app = {
            "platform": "Android", "package": self.pkg, "version": self.mi.version,
            "min_sdk": self.mi.min_sdk, "target_sdk": self.mi.target_sdk, "sha256": self.sha256,
            "permissions": sorted(self.mi.permissions), "exported_components": [f"{t}: {n}" + (f" (perm {p})" if p else "")
                                                                                for t, n, p in self.mi.exported],
            "dex_files": len(dexes), "classes": len(self.idx.classes), "app_classes": len(app_classes),
            "native_libs": sorted({n.split("/")[-1] for n in self.names if n.startswith("lib/") and n.endswith(".so")}),
            "frameworks": frameworks, "trackers": trackers, "signing": sig,
        }
        if "Flutter" in frameworks:
            self.notes.append("Flutter app: Dart code is compiled into libapp.so and is only checked for strings/secrets.")
        if "React Native" in frameworks:
            self.notes.append("React Native app: JavaScript bundle scanned for secrets and URLs only.")
        return ScanResult(self.path, "apk", app, self.c.results(), len(self.names), self.notes)

    def _class_prefix_sample(self, prefix):
        for k in self.idx.classes:
            if k.startswith(prefix):
                return [k]
        return []

    def detect_frameworks(self):
        fw = []
        if any(n.endswith("libflutter.so") for n in self.names):
            fw.append("Flutter")
        if any(n.endswith("index.android.bundle") for n in self.names) or any(n.endswith("libreactnativejni.so") for n in self.names):
            fw.append("React Native")
        if any("Xamarin" in n or n.endswith("libmonodroid.so") for n in self.names):
            fw.append("Xamarin / .NET MAUI")
        if any(n.endswith("libunity.so") for n in self.names):
            fw.append("Unity")
        if any(n.startswith("assets/www/") or n.endswith("cordova.js") for n in self.names):
            fw.append("Cordova / Ionic")
        if any(k.startswith("Lkotlin/") for k in list(self.idx.classes)[:5000]):
            fw.append("Kotlin")
        return fw

    # ------------------------------------------------------------ code (DEX)
    def code_checks(self):
        idx, mi = self.idx, self.mi
        min_sdk = mi.min_sdk or 1

        # ---- WebView
        for dx, m in self.calls("Landroid/webkit/WebView;->addJavascriptInterface"):
            self.ev("AND-WEBVIEW-JSI", dx, m, "WebView.addJavascriptInterface(...)",
                    severity="high" if min_sdk < 17 else "medium",
                    note="minSdk < 17: any page loaded can run arbitrary Java via reflection." if min_sdk < 17 else "")
        for api in ("setAllowFileAccessFromFileURLs", "setAllowUniversalAccessFromFileURLs", "setAllowFileAccess"):
            for dx, m, lits in idx.literal_calls.get(f"Landroid/webkit/WebSettings;->{api}", []):
                val = lits[1] if len(lits) > 1 else None
                if val == 1 or (val is None and api != "setAllowFileAccess"):
                    self.ev("AND-WEBVIEW-FILE", dx, m, f"WebSettings.{api}({'true' if val == 1 else '?'})",
                            severity="medium" if api == "setAllowFileAccess" else None)
        for dx, m, lits in idx.literal_calls.get("Landroid/webkit/WebSettings;->setJavaScriptEnabled", []):
            if (lits[1] if len(lits) > 1 else None) in (1, None):
                self.ev("AND-WEBVIEW-JS", dx, m, "WebSettings.setJavaScriptEnabled(true)")
        for dx, m, lits in idx.literal_calls.get("Landroid/webkit/WebView;->setWebContentsDebuggingEnabled", []):
            if (lits[0] if lits else None) in (1, None):
                self.ev("AND-WEBVIEW-DEBUG", dx, m, "WebView.setWebContentsDebuggingEnabled(true)")
        for dx, m in self.calls("Landroid/webkit/SslErrorHandler;->proceed"):
            self.ev("AND-WEBVIEW-SSL", dx, m, "SslErrorHandler.proceed() inside " + m.name)

        # ---- TLS
        for iface in ("Ljavax/net/ssl/X509TrustManager;",):
            for dx, cd in idx.implementors(iface) + idx.subclasses("Ljavax/net/ssl/X509ExtendedTrustManager;"):
                for m in idx.class_methods(dx, cd):
                    if m.name == "checkServerTrusted" and m.code_units and m.code_units <= 1 and (m.insns[0] & 0xFF) == 0x0E:
                        self.ev("AND-TLS-TRUST-ALL", dx, m, f"{cd.name[1:-1].replace('/', '.')}.checkServerTrusted() is empty")
        for dx, cd in idx.implementors("Ljavax/net/ssl/HostnameVerifier;"):
            for m in idx.class_methods(dx, cd):
                if m.name == "verify" and m.code_units == 2 and (m.insns[0] & 0xFF) == 0x12 \
                        and (m.insns[0] >> 12) == 1 and (m.insns[1] & 0xFF) == 0x0F:
                    self.ev("AND-TLS-HOSTNAME", dx, m, "HostnameVerifier.verify() always returns true")
        for f in ("Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER",):
            for dx, m in idx.field_users.get(f, []):
                self.ev("AND-TLS-HOSTNAME", dx, m, "uses SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER")
        for api in ("Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;-><init>",
                    "Lorg/apache/http/conn/ssl/NoopHostnameVerifier;-><init>"):
            for dx, m in self.calls(api):
                self.ev("AND-TLS-HOSTNAME", dx, m, api.split(";")[0].rsplit("/", 1)[-1] + " instantiated")
        for dx, m in self.calls("Landroid/net/SSLCertificateSocketFactory;->getInsecure"):
            self.ev("AND-TLS-INSECURE-FACTORY", dx, m, "SSLCertificateSocketFactory.getInsecure()")
        if self.calls("Lokhttp3/CertificatePinner$Builder;->add") or self.calls("Lcom/datatheorem/android/trustkit/TrustKit;->initializeWithNetworkSecurityConfiguration"):
            self.pinning = True

        # ---- crypto
        cipher_users = {id(m): (dx, m) for dx, m in self.calls("Ljavax/crypto/Cipher;->getInstance")}
        for s, users in idx.string_users.items():
            if not CIPHER_RX.match(s):
                continue
            for dx, m in users:
                if id(m) not in cipher_users and not any(c.endswith("Cipher;->getInstance") for c in idx.method_calls(dx, m)):
                    continue
                algo = s.upper()
                if algo == "AES" and any(x.upper().startswith("AES/") for x in idx.method_strings(dx, m)):
                    continue  # bare "AES" is the SecretKeySpec algorithm, the Cipher uses the full transformation
                if algo.startswith(("DES", "TRIPLEDES", "RC4", "ARCFOUR", "BLOWFISH", "RC2")):
                    self.ev("AND-CRYPTO-WEAK-CIPHER", dx, m, f'Cipher.getInstance("{s}")')
                elif algo.startswith("AES") and ("/ECB/" in algo or algo == "AES"):
                    self.ev("AND-CRYPTO-ECB", dx, m, f'Cipher.getInstance("{s}")' + (" (defaults to AES/ECB/PKCS5Padding)" if algo == "AES" else ""))
                elif algo.startswith("RSA") and ("NOPADDING" in algo or algo.endswith("PKCS1PADDING") or algo == "RSA"):
                    self.ev("AND-CRYPTO-RSA-NOPAD", dx, m, f'Cipher.getInstance("{s}")')
                elif "/CBC/" in algo:
                    cls_calls_mac = any(c.startswith("Ljavax/crypto/Mac;") for mm in self._class_methods_of(dx, m.cls)
                                        for c in idx.method_calls(dx, mm))
                    if not cls_calls_mac:
                        self.ev("AND-CRYPTO-CBC", dx, m, f'Cipher.getInstance("{s}") with no Mac in the same class')
        for dx, m in self.calls("Ljava/security/MessageDigest;->getInstance"):
            weak = [s for s in idx.method_strings(dx, m) if s.upper().replace("-", "") in ("MD5", "SHA1", "MD4", "MD2", "SHA")]
            if weak:
                self.ev("AND-CRYPTO-WEAK-HASH", dx, m, f'MessageDigest.getInstance("{weak[0]}")')
        for api in ("Lorg/apache/commons/codec/digest/DigestUtils;->md5Hex", "Lorg/apache/commons/codec/digest/DigestUtils;->sha1Hex"):
            for dx, m in self.calls(api):
                self.ev("AND-CRYPTO-WEAK-HASH", dx, m, api.split("->")[1] + "()")
        for api, label in (("Ljavax/crypto/spec/SecretKeySpec;-><init>", "SecretKeySpec"),
                           ("Ljavax/crypto/spec/IvParameterSpec;-><init>", "IvParameterSpec")):
            for dx, m in self.calls(api):
                strs = [s for s in idx.method_strings(dx, m) if _key_like(s)]
                uses_random = any("SecureRandom" in c for c in idx.method_calls(dx, m))
                if not strs and not m.has_array_data and not uses_random:
                    # key often lives in a field set by the constructor / static initializer
                    for mm in self._class_methods_of(dx, m.cls):
                        if mm.name in ("<init>", "<clinit>"):
                            strs += [s for s in idx.method_strings(dx, mm) if _key_like(s)]
                    if strs:
                        self.ev("AND-CRYPTO-HARDCODED-KEY", dx, m, f"{label} uses a value from a class field initialised with: " +
                                ", ".join(f'"{S.mask(s)}"' for s in strs[:3]))
                        continue
                if strs:
                    self.ev("AND-CRYPTO-HARDCODED-KEY", dx, m, f"{label} built near string constant(s): " +
                            ", ".join(f'"{S.mask(s)}"' for s in strs[:3]))
                elif m.has_array_data and not uses_random:
                    self.ev("AND-CRYPTO-HARDCODED-KEY", dx, m, f"{label} built from a static byte[] literal",
                            severity="medium" if label == "IvParameterSpec" else None)
        for dx, m in self.calls("Ljava/util/Random;-><init>"):
            if self.is_app(m.cls):
                self.ev("AND-CRYPTO-RANDOM", dx, m, "new java.util.Random()")
        for dx, m in self.calls("Ljava/security/SecureRandom;->setSeed") + self.calls("Ljava/security/SecureRandom;-><init>", "([B)"):
            self.ev("AND-CRYPTO-SEED", dx, m, "SecureRandom seeded explicitly")

        # ---- storage
        for api in ("Landroid/content/Context;->getSharedPreferences", "Landroid/content/Context;->openFileOutput",
                    "Landroid/content/ContextWrapper;->getSharedPreferences", "Landroid/content/ContextWrapper;->openFileOutput",
                    "Landroid/content/Context;->openOrCreateDatabase", "Landroid/content/ContextWrapper;->openOrCreateDatabase"):
            for dx, m, lits in idx.literal_calls.get(api, []):
                mode = lits[2] if len(lits) > 2 else None
                if mode in (1, 2, 3):
                    self.ev("AND-WORLD-READABLE", dx, m, f"{api.split('->')[1]}(..., MODE_WORLD_{'READABLE' if mode & 1 else 'WRITEABLE'})")
        for dx, m in self.calls("Landroid/content/SharedPreferences$Editor;->putString"):
            keys = [s for s in idx.method_strings(dx, m) if SECRET_WORDS.search(s) and len(s) < 40]
            if keys:
                self.ev("AND-PREFS-SECRETS", dx, m, "SharedPreferences.putString with key(s): " + ", ".join(f'"{k}"' for k in keys[:4]))
        for api in ("Landroid/os/Environment;->getExternalStorageDirectory", "Landroid/os/Environment;->getExternalStoragePublicDirectory",
                    "Landroid/content/Context;->getExternalFilesDir", "Landroid/content/ContextWrapper;->getExternalFilesDir",
                    "Landroid/content/Context;->getExternalCacheDir"):
            for dx, m in self.calls(api):
                if self.is_app(m.cls):
                    self.ev("AND-EXTERNAL-STORAGE", dx, m, api.split("->")[1] + "()")
        has_cipher_db = any(k.startswith(("Lnet/sqlcipher/", "Lnet/zetetic/")) for k in self.idx.classes)
        if not has_cipher_db:
            db_apis = [k for k in idx.callers if k.endswith(("->getWritableDatabase", "->getReadableDatabase"))]
            db_apis += ["Landroid/database/sqlite/SQLiteDatabase;->openOrCreateDatabase",
                        "Landroid/content/Context;->openOrCreateDatabase", "Landroid/content/ContextWrapper;->openOrCreateDatabase"]
            for api in db_apis:
                for dx, m in self.calls(api):
                    if self.is_app(m.cls):
                        self.ev("AND-SQLITE-PLAIN", dx, m, api.split("->")[1] + "() without SQLCipher")
        for api in ("Landroid/database/sqlite/SQLiteDatabase;->rawQuery", "Landroid/database/sqlite/SQLiteDatabase;->execSQL",
                    "Lnet/sqlcipher/database/SQLiteDatabase;->rawQuery", "Lnet/sqlcipher/database/SQLiteDatabase;->execSQL",
                    "Landroid/database/sqlite/SQLiteQueryBuilder;->appendWhere"):
            for dx, m in self.calls(api):
                calls = idx.method_calls(dx, m)
                builds = any(c.endswith(("StringBuilder;->append", "String;->concat", "String;->format")) for c in calls)
                sql = [s for s in idx.method_strings(dx, m) if SQL_RX.search(s)]
                if builds and (sql or api.endswith("appendWhere")):
                    shown = sql[0][:80] if sql else " + ".join(s for s in idx.method_strings(dx, m) if "=" in s)[:80]
                    self.ev("AND-SQLI", dx, m, f"{api.split('->')[1]}() with concatenated SQL: \"{shown}\"")

        # ---- logging / leaks
        log_hits = []
        for lvl in ("v", "d", "i", "w", "e", "wtf"):
            log_hits += self.calls(f"Landroid/util/Log;->{lvl}")
        sensitive = False
        for dx, m in log_hits:
            if not self.is_app(m.cls):
                continue
            secret_strs = [s for s in idx.method_strings(dx, m) if SECRET_WORDS.search(s) and len(s) < 120]
            sensitive |= bool(secret_strs)
            self.ev("AND-LOGGING", dx, m, "android.util.Log call" + (f" near: \"{secret_strs[0][:60]}\"" if secret_strs else ""),
                    severity="medium" if secret_strs else None)
        for api in ("Landroid/content/ClipboardManager;->setPrimaryClip", "Landroid/text/ClipboardManager;->setText",
                    "Landroid/content/ClipboardManager;->setText"):
            for dx, m in self.calls(api):
                if self.is_app(m.cls):
                    self.ev("AND-CLIPBOARD", dx, m, api.split("->")[1] + "()")

        # ---- code execution / loading
        for api in ("Ljava/lang/Runtime;->exec", "Ljava/lang/ProcessBuilder;-><init>"):
            for dx, m in self.calls(api):
                cmds = [s for s in idx.method_strings(dx, m) if len(s) < 80][:3]
                self.ev("AND-EXEC", dx, m, api.split(";")[0].rsplit("/", 1)[-1] + "." + api.split("->")[1] + f"() strings: {cmds}")
        for api in ("Ldalvik/system/DexClassLoader;-><init>", "Ldalvik/system/InMemoryDexClassLoader;-><init>"):
            for dx, m in self.calls(api):
                self.ev("AND-DYNAMIC-CODE", dx, m, api.split(";")[0].rsplit("/", 1)[-1] + " created")

        # ---- IPC
        for api in ("Landroid/content/Context;->sendBroadcast", "Landroid/content/ContextWrapper;->sendBroadcast",
                    "Landroid/app/Activity;->sendBroadcast"):
            for dx, m in self.calls(api, "(Landroid/content/Intent;)"):
                if self.is_app(m.cls):
                    self.ev("AND-IMPLICIT-BROADCAST", dx, m, "sendBroadcast(intent) without receiver permission")
        exported = {"L" + n.replace(".", "/") + ";" for _t, n, p in mi.exported if not p}
        for dx, m in self.calls("Landroid/content/Intent;->getParcelableExtra"):
            if m.cls in exported:
                calls = idx.method_calls(dx, m)
                if any(c.endswith(("->startActivity", "->startService", "->sendBroadcast", "->startActivityForResult")) for c in calls):
                    self.ev("AND-INTENT-REDIRECT", dx, m, "Intent from getParcelableExtra() is launched in an exported component")
        for dx, m in self.calls("Ljava/util/zip/ZipEntry;->getName"):
            calls = idx.method_calls(dx, m)
            writes = any(c.startswith(("Ljava/io/FileOutputStream;-><init>", "Ljava/io/File;-><init>")) for c in calls)
            checks = any(c.endswith(("->getCanonicalPath", "->getCanonicalFile", "->normalize", "->toRealPath")) for c in calls)
            if writes and not checks and self.is_app(m.cls):
                self.ev("AND-ZIP-SLIP", dx, m, "ZipEntry.getName() used to create a file without canonical-path check")
        for dx, m, lits in idx.literal_calls.get("Landroid/app/PendingIntent;->getActivity", []) + \
                idx.literal_calls.get("Landroid/app/PendingIntent;->getService", []) + \
                idx.literal_calls.get("Landroid/app/PendingIntent;->getBroadcast", []):
            flags = lits[3] if len(lits) > 3 else None
            if isinstance(flags, int) and flags & 0x02000000 and self.is_app(m.cls):
                self.ev("AND-PENDING-INTENT", dx, m, "PendingIntent created with FLAG_MUTABLE", severity="low")

        # ---- auth
        for api, proto in (("Landroidx/biometric/BiometricPrompt;->authenticate", "(Landroidx/biometric/BiometricPrompt$PromptInfo;)"),
                           ("Landroid/hardware/biometrics/BiometricPrompt;->authenticate", "(Landroid/os/CancellationSignal;"),
                           ("Landroidx/core/hardware/fingerprint/FingerprintManagerCompat;->authenticate", None)):
            for dx, m in self.calls(api, proto):
                if self.is_app(m.cls):
                    self.ev("AND-BIOMETRIC-NO-CRYPTO", dx, m, api.split(";")[0].rsplit("/", 1)[-1] + ".authenticate() without CryptoObject")

        # ---- screenshots
        secure = False
        for api in ("Landroid/view/Window;->setFlags", "Landroid/view/Window;->addFlags"):
            for _dx, _m, lits in idx.literal_calls.get(api, []):
                flag = lits[1] if len(lits) > 1 else None
                if flag is None or (isinstance(flag, int) and flag & 0x2000):
                    secure = True
        if not secure:
            self.c.add("AND-NO-FLAG-SECURE", "classes*.dex", 0, "No Window.setFlags/addFlags(FLAG_SECURE) call found")

        # ---- resilience
        root_hint = any(ROOT_HINTS.search(s) for s in idx.strings) or any(
            k.startswith(("Lcom/scottyab/rootbeer/", "Lcom/google/android/play/core/integrity/", "Lcom/google/android/gms/safetynet/"))
            for k in idx.classes)
        if not root_hint:
            self.c.add("AND-NO-ROOT-DETECTION", "classes*.dex", 0, "No root-detection strings or Play Integrity / SafetyNet classes found")
        app_cls = [k for k in idx.classes if self.pkg_path and k.startswith(self.pkg_path)]
        if len(app_cls) > 10:
            readable = sum(1 for k in app_cls if len(k.rsplit("/", 1)[-1].rstrip(";").split("$")[0]) > 2)
            if readable / len(app_cls) > 0.8:
                self.c.add("AND-NOT-OBFUSCATED", "classes*.dex", 0,
                           f"{readable}/{len(app_cls)} app classes keep readable names (e.g. {app_cls[0][1:-1].replace('/', '.')})")

        # ---- network: URLs, pinning
        net = False
        for s, users in idx.string_users.items():
            if s.startswith("http://") and len(s) > 10 and not URL_IGNORE.match(s):
                for dx, m in users[:3]:
                    self.ev("AND-HTTP-URL", dx, m, s[:150])
            if s.startswith(("http://", "https://")):
                net = True
        if net and not self.pinning:
            self.c.add("AND-NO-PINNING", "classes*.dex", 0, "No <pin-set>, OkHttp CertificatePinner or TrustKit found")

    def _class_methods_of(self, dx, cls):
        pair = self.idx.classes.get(cls)
        return self.idx.class_methods(*pair) if pair else []

    # ------------------------------------------------------------ native
    def native_checks(self):
        libs = [n for n in self.names if n.startswith("lib/") and n.endswith(".so")]
        abis = {n.split("/")[1] for n in libs}
        abi = next((a for a in ("arm64-v8a", "armeabi-v7a", "armeabi", "x86_64", "x86") if a in abis), None)
        known_tp = re.compile(r"lib(flutter|app|sqlcipher|c\+\+_shared|jsc|hermes|reactnative|fb|crashlytics|realm|"
                              r"stlport|gnustl|unity|il2cpp|main|mono|xamarin|sentry|conscrypt|tensorflow|opencv|"
                              r"database_sqlcipher|imagepipeline|yoga|glog|folly|v8|monochrome|webp|gif|jpeg|png)", re.I)
        for n in libs:
            if abi and n.split("/")[1] != abi:
                continue
            try:
                e = elf.parse(self.z.read(n))
            except Exception:
                continue
            tp = bool(known_tp.search(n.rsplit("/", 1)[-1]))
            if not e.nx:
                self.c.add("AND-NATIVE-NX", n, 0, "PT_GNU_STACK is executable or missing", third_party=tp)
            if not e.stack_canary and e.imports:
                self.c.add("AND-NATIVE-CANARY", n, 0, "__stack_chk_fail not imported", third_party=tp)
            if e.relro != "full":
                self.c.add("AND-NATIVE-RELRO", n, 0, f"RELRO: {e.relro}", third_party=tp)
            if e.dangerous:
                self.c.add("AND-NATIVE-UNSAFE", n, 0, ", ".join(e.dangerous), third_party=tp)

    # ------------------------------------------------------------ signing
    def signing_checks(self):
        certs = [n for n in self.names if re.fullmatch(r"META-INF/[^/]+\.(RSA|DSA|EC)", n)]
        tail = self.raw[-min(len(self.raw), 4_000_000):]
        v2 = b"APK Sig Block 42" in tail
        schemes = (["v1"] if certs else []) + (["v2+"] if v2 else [])
        debug = any(b"Android Debug" in self.z.read(n) for n in certs) or (v2 and b"Android Debug" in tail[-400_000:])
        self.signature_info = {"schemes": schemes or ["unsigned?"], "debug_certificate": debug}
        if certs and not v2 and (self.mi.min_sdk or 1) < 24:
            self.c.add("AND-SIGN-V1-ONLY", "META-INF/", 0, "Only JAR (v1) signature present; vulnerable to Janus on Android 5.0-8.0")
        if debug:
            self.c.add("AND-DEBUG-CERT", certs[0] if certs else "APK Signing Block", 0, "Certificate subject contains 'Android Debug'")

    # ------------------------------------------------------------ secrets
    def secret_checks(self):
        for s, users in self.idx.string_users.items():
            if len(s) < 16 or len(s) > 4000:
                continue
            for kind, val, sev, _ in S.scan_text(s, assignments=False):
                dx, m = users[0]
                self.ev("SEC-HARDCODED", dx, m, f"{kind}: {S.mask(val)}", severity=sev if sev != "info" else "low")
            if S.FIREBASE.search(s):
                dx, m = users[0]
                self.ev("SEC-FIREBASE", dx, m, S.FIREBASE.search(s).group(0))
            if S.BUCKET.search(s):
                dx, m = users[0]
                self.ev("SEC-CLOUD-BUCKET", dx, m, S.BUCKET.search(s).group(0)[:120])
        try:
            res_strings = arsc.strings(self.z.read("resources.arsc")) if "resources.arsc" in self.names else []
        except Exception:
            res_strings = []
        for s in res_strings:
            for kind, val, sev, _ in S.scan_text(s, assignments=False):
                self.c.add("SEC-HARDCODED", "resources.arsc (strings.xml)", 0, f"{kind}: {S.mask(val)}",
                           severity=sev if sev != "info" else "low")
            if S.FIREBASE.search(s):
                self.c.add("SEC-FIREBASE", "resources.arsc (strings.xml)", 0, S.FIREBASE.search(s).group(0))
        for n in self.names:
            low = n.lower()
            info = self.z.getinfo(n)
            if low.endswith(KEY_EXT) and not low.startswith("meta-inf/"):
                self.c.add("SEC-PRIVATE-KEY", n, 0, f"Key/certificate container bundled ({info.file_size} bytes)",
                           severity="medium" if low.endswith((".der", ".pem")) else None)
                continue
            if (low.startswith(("assets/", "res/raw/")) and low.endswith(TEXT_EXT)) and info.file_size < 8_000_000:
                try:
                    text = self.z.read(n).decode("utf-8", "ignore")
                except Exception:
                    continue
                for kind, val, sev, off in S.scan_text(text):
                    line = text.count("\n", 0, off) + 1
                    self.c.add("SEC-HARDCODED", n, line, f"{kind}: {S.mask(val)}", severity=sev if sev != "info" else "low")
                for rx, rule in ((S.FIREBASE, "SEC-FIREBASE"), (S.BUCKET, "SEC-CLOUD-BUCKET")):
                    mm = rx.search(text)
                    if mm:
                        self.c.add(rule, n, text.count("\n", 0, mm.start()) + 1, mm.group(0)[:120])
                if "PRIVATE KEY-----" in text:
                    self.c.add("SEC-PRIVATE-KEY", n, 0, "PEM private key in bundled file")


def analyze(path: str) -> ScanResult:
    return APKAnalyzer(path).run()
