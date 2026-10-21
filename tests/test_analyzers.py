import json
import plistlib

from mobsec.android.apk import APKAnalyzer
from mobsec.ios.ipa import IPAAnalyzer
from mobsec.source.scanner import scan
from mobsec import secrets
from helpers import vulnerable_manifest, make_apk, make_macho, make_ipa


def ids(result):
    return {f.rule_id for f in result.findings}


def test_apk_manifest_findings(tmp_path):
    p = tmp_path / "demo.apk"
    p.write_bytes(make_apk(vulnerable_manifest(), {"assets/config.json": '{"aws": "AKIAABCDEFGHIJKLMNOP"}',
                                                   "assets/server.p12": b"\x30\x82"}))
    r = APKAnalyzer(str(p)).run()
    found = ids(r)
    assert {"AND-DEBUGGABLE", "AND-ALLOW-BACKUP", "AND-EXPORTED-ACTIVITY", "AND-EXPORTED-PROVIDER",
            "AND-CLEARTEXT", "AND-OLD-MINSDK", "SEC-HARDCODED", "SEC-PRIVATE-KEY"} <= found
    exported = next(f for f in r.findings if f.rule_id == "AND-EXPORTED-ACTIVITY")
    assert all("MainActivity" not in e.snippet for e in exported.evidence)  # launcher excluded
    assert all("SafeService" not in e.snippet for f in r.findings for e in f.evidence)
    assert r.app["package"] == "com.example.bank"


def test_ipa_findings(tmp_path):
    info = {"CFBundleIdentifier": "com.example.demo", "CFBundleExecutable": "Demo", "MinimumOSVersion": "12.0",
            "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
            "CFBundleURLTypes": [{"CFBundleURLSchemes": ["demo"]}]}
    binary = make_macho(["_CC_MD5", "_kSecAttrAccessibleAlways", "_NSFileProtectionNone", "_OBJC_CLASS_$_UIWebView",
                         "___stack_chk_guard", "_objc_release"],
                        strings=["http://api.example.org/login", "SELECT * FROM users WHERE name = '%@'",
                                 "sk_live_abcdefghijklmnop1234"], entitlements={"get-task-allow": True})
    p = tmp_path / "demo.ipa"
    p.write_bytes(make_ipa(info, binary, {"DeviceInfo.h": "// header"}))
    r = IPAAnalyzer(str(p)).run()
    found = ids(r)
    assert {"IOS-ATS-ARBITRARY", "IOS-GET-TASK-ALLOW", "IOS-WEAK-HASH", "IOS-KEYCHAIN-WEAK", "IOS-FILE-PROTECTION-NONE",
            "IOS-UIWEBVIEW", "IOS-HTTP-URL", "IOS-URL-SCHEME", "IOS-OLD-MINOS", "SEC-HARDCODED",
            "IOS-BUNDLED-HEADERS", "IOS-NO-PRIVACY-MANIFEST"} <= found
    assert "IOS-NO-PIE" not in found


def test_source_scan_reports_file_and_line(tmp_path):
    (tmp_path / "app/src/main/java/com/ex").mkdir(parents=True)
    (tmp_path / "app/src/main/AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.ex">\n'
        '  <application android:allowBackup="true" android:usesCleartextTraffic="true">\n'
        '    <activity android:name=".Admin" android:exported="true"/>\n'
        '  </application>\n</manifest>\n')
    (tmp_path / "app/build.gradle").write_text(
        "android {\n  defaultConfig { minSdkVersion 21\n targetSdkVersion 34 }\n  buildTypes {\n    release {\n      minifyEnabled false\n    }\n  }\n}\n")
    (tmp_path / "app/src/main/java/com/ex/Crypto.java").write_text(
        'class Crypto {\n'
        '  String key = "ThisIsMyHardcodedKey!";\n'
        '  Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");\n'
        '  void q(SQLiteDatabase db, String u) { db.rawQuery("SELECT * FROM users WHERE name = \'" + u + "\'", null); }\n'
        '  // Log.d("x", password)  <- commented out\n'
        '}\n')
    (tmp_path / "ios/App").mkdir(parents=True)
    (tmp_path / "ios/App/Store.swift").write_text(
        'import Foundation\nfunc save(t: String) {\n  UserDefaults.standard.set(t, forKey: "authToken")\n}\n')
    r = scan(str(tmp_path))
    by = {f.rule_id: f for f in r.findings}
    assert by["AND-CRYPTO-ECB"].evidence[0].location.endswith("Crypto.java")
    assert by["AND-CRYPTO-ECB"].evidence[0].line == 3
    assert by["AND-CRYPTO-HARDCODED-KEY"].evidence[0].line == 2
    assert by["AND-SQLI"].evidence[0].line == 4
    assert by["AND-NOT-OBFUSCATED"].evidence[0].location == "app/build.gradle"
    assert by["IOS-USERDEFAULTS-SECRETS"].evidence[0].line == 3
    assert {"AND-ALLOW-BACKUP", "AND-CLEARTEXT", "AND-EXPORTED-ACTIVITY"} <= set(by)
    assert "AND-LOGGING" not in by  # commented-out line ignored


def test_secret_patterns_and_mask():
    hits = list(secrets.scan_text('aws="AKIAABCDEFGHIJKLMNOP" password = "hunter2hunter2"'))
    kinds = {h[0] for h in hits}
    assert "AWS access key" in kinds
    assert any("password" in k for k in kinds)
    assert secrets.mask("AKIAABCDEFGHIJKLMNOP").startswith("AKIAAB") and "…" in secrets.mask("AKIAABCDEFGHIJKLMNOP")
    assert not list(secrets.scan_text('PASSWORD_PATTERN = "((?=.*\\\\d).{6,20})"'))


def test_hardening_source_checklist_and_profile(tmp_path):
    from mobsec.hardening import apply_profile
    (tmp_path / "app/src/main/java/com/ex").mkdir(parents=True)
    (tmp_path / "app/src/main/AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.ex"><application/></manifest>')
    (tmp_path / "app/proguard-rules.pro").write_text("-dontobfuscate\n-keepattributes SourceFile,LineNumberTable\n")
    (tmp_path / "app/src/main/java/com/ex/Guard.kt").write_text(
        'fun frida() = java.io.File("/proc/self/maps").readText().contains("frida")\n'
        'fun dbg() = android.os.Debug.isDebuggerConnected()\n')
    r = scan(str(tmp_path))
    found = ids(r)
    assert {"AND-NOT-OBFUSCATED", "AND-DEBUG-INFO-RETAINED", "AND-NO-TAMPER-CHECK", "AND-NO-ROOT-DETECTION"} <= found
    assert "AND-NO-HOOK-DETECTION" not in found and "AND-NO-ANTI-DEBUG" not in found
    rows = {row["control"]: row for row in r.app["hardening"]["checklist"]}
    assert rows["Anti-debugging"]["status"] == "present" and "Guard.kt:2" in rows["Anti-debugging"]["evidence"]
    assert rows["Root detection"]["status"] == "missing"
    root = next(f for f in r.findings if f.rule_id == "AND-NO-ROOT-DETECTION")
    assert root.severity == "info"
    apply_profile(r.findings, "high-risk")
    assert root.severity == "medium"


def test_hardening_ipa(tmp_path):
    info = {"CFBundleIdentifier": "com.example.demo", "CFBundleExecutable": "Demo"}
    binary = make_macho(["_ptrace", "___stack_chk_guard", "_objc_release"],
                        strings=["/Applications/Cydia.app", "FridaGadget", "AccountViewController", "PaymentManager",
                                 "LoginViewController", "SettingsViewController"] + [f"Screen{i}Controller" for i in range(30)])
    p = tmp_path / "demo.ipa"
    p.write_bytes(make_ipa(info, binary))
    r = IPAAnalyzer(str(p)).run()
    found = ids(r)
    assert not {"IOS-NO-ANTI-DEBUG", "IOS-NO-JB-DETECTION", "IOS-NO-HOOK-DETECTION"} & found
    assert {"IOS-NO-TAMPER-CHECK", "IOS-NO-ATTESTATION", "IOS-NO-SCREEN-PROTECTION", "IOS-NOT-OBFUSCATED"} <= found
