"""AndroidManifest.xml and network_security_config.xml checks.

Works on an ElementTree root whose android-namespace attributes are keyed
"android:<name>" - produced by the AXML parser (APK) or by `load_text_xml`
(source projects).
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ..finding import Collector

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

DANGEROUS_PERMS = {
    "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION", "CAMERA", "RECORD_AUDIO", "READ_SMS", "SEND_SMS", "RECEIVE_SMS",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS", "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
    "CALL_PHONE", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE",
    "BODY_SENSORS", "READ_CALENDAR", "WRITE_CALENDAR", "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES",
    "QUERY_ALL_PACKAGES", "BIND_ACCESSIBILITY_SERVICE", "PACKAGE_USAGE_STATS", "READ_MEDIA_IMAGES",
    "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO", "ACTIVITY_RECOGNITION", "BLUETOOTH_SCAN", "NEARBY_WIFI_DEVICES",
    "USE_SIP", "ANSWER_PHONE_CALLS", "WRITE_SETTINGS", "BIND_DEVICE_ADMIN", "READ_PRIVILEGED_PHONE_STATE",
}
COMPONENTS = {"activity": "AND-EXPORTED-ACTIVITY", "activity-alias": "AND-EXPORTED-ACTIVITY",
              "service": "AND-EXPORTED-SERVICE", "receiver": "AND-EXPORTED-RECEIVER",
              "provider": "AND-EXPORTED-PROVIDER"}
WEAK_LEVELS = {"0", "1", "normal", "dangerous", "0x0", "0x1"}


def load_text_xml(text: str) -> ET.Element:
    """Parse a plain-text XML file and rename {android-ns}attr -> android:attr."""
    root = ET.fromstring(text)
    for el in root.iter():
        for k in list(el.attrib):
            if k.startswith(ANDROID_NS):
                el.set("android:" + k[len(ANDROID_NS):], el.attrib.pop(k))
            elif k.startswith("{"):
                el.set(k.split("}", 1)[1], el.attrib.pop(k))
    return root


def _int(v, default=None):
    if v is None:
        return default
    try:
        return int(v, 0) if isinstance(v, str) else int(v)
    except ValueError:
        return default


def _true(v) -> bool:
    return str(v).lower() in ("true", "1", "0xffffffff", "-1")


def line_of(text: str | None, needle: str) -> int:
    if not text or not needle:
        return 0
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else 0


def _full_name(name: str, pkg: str) -> str:
    if name.startswith("."):
        return pkg + name
    if "." not in name:
        return f"{pkg}.{name}"
    return name


class ManifestInfo:
    def __init__(self, root: ET.Element, sdk_override: dict | None = None):
        self.root = root
        self.package = root.get("package", "")
        sdk = root.find("uses-sdk")
        self.min_sdk = _int(sdk.get("android:minSdkVersion") if sdk is not None else None)
        self.target_sdk = _int(sdk.get("android:targetSdkVersion") if sdk is not None else None)
        if sdk_override:
            self.min_sdk = self.min_sdk or sdk_override.get("min")
            self.target_sdk = self.target_sdk or sdk_override.get("target")
            self.package = self.package or sdk_override.get("package", "")
        self.target_sdk = self.target_sdk or self.min_sdk
        self.version = root.get("android:versionName", "")
        self.app = root.find("application")
        self.permissions = [p.get("android:name", "") for p in root.iter("uses-permission")]
        self.custom_perms = {p.get("android:name", ""): p.get("android:protectionLevel", "0")
                             for p in root.iter("permission")}
        self.nsc_ref = self.app.get("android:networkSecurityConfig") if self.app is not None else None
        self.exported = []


def check_manifest(root: ET.Element, c: Collector, loc: str, text: str | None = None,
                   sdk_override: dict | None = None) -> ManifestInfo:
    mi = ManifestInfo(root, sdk_override)
    app = mi.app
    if app is None:
        return mi
    pkg = mi.package
    ln = lambda needle: line_of(text, needle)

    if _true(app.get("android:debuggable")):
        c.add("AND-DEBUGGABLE", loc, ln("debuggable"), 'android:debuggable="true"')
    if _true(app.get("android:testOnly")):
        c.add("AND-TEST-ONLY", loc, ln("testOnly"), 'android:testOnly="true"')

    backup = app.get("android:allowBackup")
    if backup is None or _true(backup):
        rules = app.get("android:dataExtractionRules") or app.get("android:fullBackupContent")
        c.add("AND-ALLOW-BACKUP", loc, ln("allowBackup"),
              'android:allowBackup="true"' if backup else "allowBackup not set (defaults to true)",
              severity="low" if rules else None,
              note="Backup rules are defined; verify they exclude sensitive files." if rules else "")

    ct = app.get("android:usesCleartextTraffic")
    if _true(ct):
        c.add("AND-CLEARTEXT", loc, ln("usesCleartextTraffic"), 'android:usesCleartextTraffic="true"')
    elif ct is None and not mi.nsc_ref and mi.target_sdk is not None and mi.target_sdk < 28:
        c.add("AND-CLEARTEXT", loc, 0, f"targetSdkVersion={mi.target_sdk}: cleartext allowed by default (< 28)",
              severity="medium")

    if root.get("android:sharedUserId"):
        c.add("AND-SHARED-UID", loc, ln("sharedUserId"), f'android:sharedUserId="{root.get("android:sharedUserId")}"')

    if mi.min_sdk is not None and mi.min_sdk < 23:
        c.add("AND-OLD-MINSDK", loc, ln("minSdk"), f"minSdkVersion={mi.min_sdk}",
              severity="medium" if mi.min_sdk < 19 else None)
    if mi.target_sdk is not None and mi.target_sdk < 33:
        c.add("AND-OLD-TARGETSDK", loc, ln("targetSdk"), f"targetSdkVersion={mi.target_sdk}")

    danger = sorted({p.rsplit(".", 1)[-1] for p in mi.permissions} & DANGEROUS_PERMS)
    if danger:
        c.add("AND-DANGEROUS-PERMS", loc, ln("uses-permission"), ", ".join(danger))
    if _true(app.get("android:requestLegacyExternalStorage")) or "android.permission.WRITE_EXTERNAL_STORAGE" in mi.permissions:
        c.add("AND-EXTERNAL-STORAGE", loc, ln("EXTERNAL_STORAGE"),
              "WRITE_EXTERNAL_STORAGE / requestLegacyExternalStorage declared", severity="low")

    for name, level in mi.custom_perms.items():
        if str(level).lower() in WEAK_LEVELS:
            c.add("AND-WEAK-PERMISSION", loc, ln(name), f'<permission android:name="{name}" protectionLevel={level or "normal"}>')

    app_affinity = app.get("android:taskAffinity")
    for comp in app:
        tag = comp.tag
        if tag not in COMPONENTS:
            continue
        name = _full_name(comp.get("android:name", comp.get("android:targetActivity", "?")), pkg)
        third = bool(pkg) and not name.startswith(pkg) and not comp.get("android:name", "").startswith(".")
        filters = comp.findall("intent-filter")
        actions = [a.get("android:name", "") for f in filters for a in f.findall("action")]
        cats = [a.get("android:name", "") for f in filters for a in f.findall("category")]
        exp = comp.get("android:exported")
        if exp is not None:
            exported = _true(exp)
        elif tag == "provider":
            exported = (mi.target_sdk or 99) < 17
        else:
            exported = bool(filters)
        if not exported or not _true(comp.get("android:enabled", "true")):
            continue
        launcher = "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in cats
        perm = comp.get("android:permission") or (
            comp.get("android:readPermission") and comp.get("android:writePermission"))
        mi.exported.append((tag, name, perm))
        if perm:
            level = mi.custom_perms.get(perm)
            if level is not None and str(level).lower() in WEAK_LEVELS:
                c.add("AND-WEAK-PERMISSION", loc, ln(name),
                      f"<{tag} {name}> protected by {perm} (protectionLevel={level or 'normal'})", third_party=third)
            continue
        if launcher:
            continue
        snippet = f'<{tag} android:name="{name}" exported={exp or "implicit (has intent-filter)"}>'
        if actions:
            snippet += " actions: " + ", ".join(actions[:4])
        c.add(COMPONENTS[tag], loc, ln(comp.get("android:name", "")), snippet, third_party=third)

        if tag in ("activity", "activity-alias"):
            lm = str(comp.get("android:launchMode", ""))
            aff = comp.get("android:taskAffinity", app_affinity)
            if (lm in ("2", "3", "singleTask", "singleInstance") and aff != "") or _true(comp.get("android:allowTaskReparenting")):
                if (mi.min_sdk or 0) < 30:
                    c.add("AND-TASK-HIJACK", loc, ln(comp.get("android:name", "")),
                          f"{name}: launchMode={lm or 'standard'} taskAffinity={aff!r}", third_party=third)

    for comp in app.iter("provider"):
        if _true(comp.get("android:grantUriPermissions")):
            nm = _full_name(comp.get("android:name", "?"), pkg)
            c.add("AND-PROVIDER-GRANT-URI", loc, ln(comp.get("android:name", "")),
                  f'{nm} authorities="{comp.get("android:authorities", "")}" grantUriPermissions=true',
                  third_party=bool(pkg) and not nm.startswith(pkg))

    # deep links
    for comp in app:
        for f in comp.findall("intent-filter"):
            cats = {x.get("android:name", "") for x in f.findall("category")}
            if "android.intent.category.BROWSABLE" not in cats:
                continue
            schemes = {d.get("android:scheme") for d in f.findall("data") if d.get("android:scheme")}
            hosts = {d.get("android:host") for d in f.findall("data") if d.get("android:host")}
            custom = schemes - {"http", "https"}
            web_unverified = (schemes & {"http", "https"}) and not _true(f.get("android:autoVerify"))
            if custom or web_unverified:
                nm = _full_name(comp.get("android:name", "?"), pkg)
                desc = f"{nm}: schemes={sorted(schemes)} hosts={sorted(hosts)}"
                if web_unverified:
                    desc += " (http/https link without autoVerify)"
                c.add("AND-DEEPLINK", loc, ln(comp.get("android:name", "")), desc)
    return mi


def check_nsc(root: ET.Element, c: Collector, loc: str, text: str | None = None) -> dict:
    """Return {'pinning': bool, 'cleartext_base': bool}."""
    info = {"pinning": False, "cleartext_base": False}
    ln = lambda needle: line_of(text, needle)
    if root.tag != "network-security-config":
        return info
    for cfg in root:
        if cfg.tag not in ("base-config", "domain-config"):
            continue  # debug-overrides is fine
        ct = cfg.get("cleartextTrafficPermitted") or cfg.get("android:cleartextTrafficPermitted")
        if _true(ct):
            if cfg.tag == "base-config":
                info["cleartext_base"] = True
                c.add("AND-CLEARTEXT", loc, ln("cleartextTrafficPermitted"), '<base-config cleartextTrafficPermitted="true">')
            else:
                doms = [d.text.strip() for d in cfg.iter("domain") if d.text]
                c.add("AND-CLEARTEXT", loc, ln("cleartextTrafficPermitted"),
                      f"<domain-config cleartextTrafficPermitted=\"true\"> for {', '.join(doms[:6])}", severity="medium")
        for ta in cfg.iter("trust-anchors"):
            for cert in ta.iter("certificates"):
                src = cert.get("src", "")
                if src == "user":
                    c.add("AND-NSC-USER-CA", loc, ln('src="user"'), f'<{cfg.tag}> trusts <certificates src="user"/>')
                if _true(cert.get("overridePins")):
                    c.add("AND-NSC-OVERRIDE-PINS", loc, ln("overridePins"), f'<certificates src="{src}" overridePins="true"/>')
        if cfg.find(".//pin-set") is not None:
            info["pinning"] = True
    return info


_NAME_RX = re.compile(r"network.?security", re.I)


def looks_like_nsc(path: str) -> bool:
    return bool(_NAME_RX.search(path)) or path.startswith("res/xml")
