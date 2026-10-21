"""Info.plist and entitlements checks (shared by IPA and Xcode source scans)."""
from __future__ import annotations

from ..finding import Collector

PERMISSION_KEYS = [
    "NSCameraUsageDescription", "NSMicrophoneUsageDescription", "NSLocationAlwaysAndWhenInUseUsageDescription",
    "NSLocationAlwaysUsageDescription", "NSLocationWhenInUseUsageDescription", "NSContactsUsageDescription",
    "NSPhotoLibraryUsageDescription", "NSPhotoLibraryAddUsageDescription", "NSBluetoothAlwaysUsageDescription",
    "NSHealthShareUsageDescription", "NSHealthUpdateUsageDescription", "NSUserTrackingUsageDescription",
    "NSFaceIDUsageDescription", "NSCalendarsUsageDescription", "NSRemindersUsageDescription",
    "NSMotionUsageDescription", "NSSpeechRecognitionUsageDescription", "NSLocalNetworkUsageDescription",
    "NSAppleMusicUsageDescription", "NFCReaderUsageDescription",
]


def _ln(text, needle):
    if not text:
        return 0
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else 0


def check_info_plist(pl: dict, c: Collector, loc: str, text: str | None = None) -> dict:
    info = {"pinning": bool((pl.get("NSAppTransportSecurity") or {}).get("NSPinnedDomains"))}
    ats = pl.get("NSAppTransportSecurity") or {}
    if ats.get("NSAllowsArbitraryLoads") is True:
        c.add("IOS-ATS-ARBITRARY", loc, _ln(text, "NSAllowsArbitraryLoads"), "NSAllowsArbitraryLoads = true")
    for k in ("NSAllowsArbitraryLoadsInWebContent", "NSAllowsArbitraryLoadsForMedia"):
        if ats.get(k) is True:
            c.add("IOS-ATS-WEB", loc, _ln(text, k), f"{k} = true")
    for domain, cfg in (ats.get("NSExceptionDomains") or {}).items():
        if not isinstance(cfg, dict):
            continue
        sub = " (+subdomains)" if cfg.get("NSIncludesSubdomains") else ""
        if cfg.get("NSExceptionAllowsInsecureHTTPLoads") or cfg.get("NSThirdPartyExceptionAllowsInsecureHTTPLoads"):
            c.add("IOS-ATS-EXCEPTION", loc, _ln(text, domain), f"{domain}{sub}: AllowsInsecureHTTPLoads = true")
        tls = cfg.get("NSExceptionMinimumTLSVersion") or cfg.get("NSThirdPartyExceptionMinimumTLSVersion")
        if tls in ("TLSv1.0", "TLSv1.1"):
            c.add("IOS-ATS-EXCEPTION", loc, _ln(text, domain), f"{domain}{sub}: MinimumTLSVersion = {tls}")
        if cfg.get("NSExceptionRequiresForwardSecrecy") is False:
            c.add("IOS-ATS-EXCEPTION", loc, _ln(text, domain), f"{domain}{sub}: RequiresForwardSecrecy = false", severity="low")
    schemes = [s for t in (pl.get("CFBundleURLTypes") or []) if isinstance(t, dict) for s in t.get("CFBundleURLSchemes", [])]
    schemes = [s for s in schemes if not s.startswith(("fb", "com.googleusercontent.apps"))] or schemes
    if schemes:
        c.add("IOS-URL-SCHEME", loc, _ln(text, "CFBundleURLSchemes"), "URL schemes: " + ", ".join(schemes[:10]))
    if pl.get("UIFileSharingEnabled") is True:
        c.add("IOS-FILE-SHARING", loc, _ln(text, "UIFileSharingEnabled"), "UIFileSharingEnabled = true" +
              (" + LSSupportsOpeningDocumentsInPlace" if pl.get("LSSupportsOpeningDocumentsInPlace") else ""))
    perms = [k.replace("UsageDescription", "") for k in PERMISSION_KEYS if k in pl]
    if perms:
        c.add("IOS-PERMISSIONS", loc, _ln(text, "UsageDescription"), "Requested: " + ", ".join(perms))
    mos = str(pl.get("MinimumOSVersion") or "")
    try:
        if mos and float(mos.split(".")[0]) < 15:
            c.add("IOS-OLD-MINOS", loc, _ln(text, "MinimumOSVersion"), f"MinimumOSVersion = {mos}")
    except ValueError:
        pass
    return info


def check_entitlements(ent: dict, c: Collector, loc: str, text: str | None = None):
    if ent.get("get-task-allow") is True:
        c.add("IOS-GET-TASK-ALLOW", loc, _ln(text, "get-task-allow"), "get-task-allow = true")
