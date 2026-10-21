# iOS Platform Interaction, Code Quality, Resilience and Privacy

## UIWebView is deprecated
Tags: MASVS-PLATFORM-2, UIWebView, WKWebView
UIWebView runs JavaScript in the app process, cannot disable JavaScript, and has been rejected by App Review for new apps and updates since 2020. Migrate to WKWebView, which runs web content out of process.

## WKWebView hardening
Tags: MASVS-PLATFORM-2, M4, CWE-749, WKWebView, WKScriptMessageHandler, userContentController, allowFileAccessFromFileURLs
Risks come from loading untrusted content while native functionality is exposed. A WKScriptMessageHandler registered via userContentController.add(_:name:) can be called by any page loaded in that web view, so validate message.frameInfo.securityOrigin and the body of every message. Avoid the private allowFileAccessFromFileURLs and allowUniversalAccessFromFileURLs settings; with loadFileURL, grant read access only to the narrowest directory. Restrict navigation to an allowlist in decidePolicyFor navigationAction and set javaScriptEnabled = false (defaultWebpagePreferences.allowsContentJavaScript) when JavaScript is not needed.

## Custom URL schemes and deep links
Tags: MASVS-PLATFORM-1, M4, CWE-939, CFBundleURLTypes, openURL, onOpenURL, universal links
Any app can register the same custom URL scheme, and iOS does not guarantee which app receives it. Treat every incoming URL as untrusted input: validate host, path and parameters, and do not perform sensitive actions (payments, account changes, auto-login) directly from a link without user confirmation. For OAuth redirects use ASWebAuthenticationSession with PKCE, or Universal Links, which are bound to your domain via apple-app-site-association.

## SQL injection in local databases
Tags: MASVS-CODE-4, CWE-89, sqlite3_bind, string interpolation
Building SQL with Swift interpolation or stringWithFormat: lets input from deep links, web views or synced data alter the query. Use prepared statements with sqlite3_prepare_v2 and sqlite3_bind_text, or an ORM like GRDB with argument binding. For Core Data use NSPredicate(format:) with %@ arguments, never by concatenating strings into the format.

## Debug code and build settings
Tags: MASVS-RESILIENCE-4, MASVS-CODE-2, get-task-allow, #if DEBUG
Debug-only switches such as skipAuth or bypassSSL left as constants ship to production. Wrap them in #if DEBUG so they are compiled out. The get-task-allow entitlement must be false in distribution builds; when true, a debugger can attach to the app. App Store builds strip it automatically, but enterprise or ad-hoc builds may not.

## Third-party dependencies
Tags: MASVS-CODE-3, M2, supply chain, CocoaPods, Swift Package Manager
Track every SDK and its version (Package.resolved, Podfile.lock). Check them against advisories (GitHub Advisory Database, OSV) and remove unused SDKs, since analytics and ad SDKs commonly collect data on the app's behalf.

## Reverse engineering resilience
Tags: MASVS-RESILIENCE-1, MASVS-RESILIENCE-2, jailbreak detection, obfuscation, M7
Jailbreak detection, anti-debugging and obfuscation raise the cost of attacks but can always be bypassed by a determined attacker. They are worth adding for high-value apps (banking, DRM, games with economies) and should never be the only protection for secrets or business logic. Use App Attest (DCAppAttestService) so your server can verify requests come from a genuine copy of the app.

## Privacy manifest and permissions
Tags: MASVS-PRIVACY-1, PrivacyInfo.xcprivacy, NSPrivacyAccessedAPITypes, usage description, M6
Apple requires a privacy manifest (PrivacyInfo.xcprivacy) declaring collected data types, tracking domains and reasons for using required-reason APIs such as UserDefaults, file timestamps and system boot time. Third-party SDKs must ship their own. Each permission in Info.plist (camera, location, contacts and so on) needs a usage description and should be requested only at the moment the feature needs it. Unused permission keys suggest data collection the user did not expect.

## iOS binary protections (PIE, stack canary, ARC, stripping)
Tags: MASVS-CODE-4, MASVS-RESILIENCE-3, M7, PIE, ASLR, stack_chk_guard, ARC, objc_release, strip, debug symbols
Xcode builds apps as position-independent executables with stack canaries and ARC by default; missing flags usually indicate very old build settings or prebuilt third-party code. PIE enables full ASLR, stack canaries (___stack_chk_guard) detect stack buffer overflows, and ARC (objc_release imports) removes most manual memory-management bugs (use-after-free). Release binaries should also be stripped (STRIP_INSTALLED_PRODUCT=YES, STRIP_STYLE=all, DEPLOYMENT_POSTPROCESSING=YES); leftover local symbols reveal class and function names that make reverse engineering easier.

## FairPlay encryption
Tags: MASVS-RESILIENCE-3, cryptid, LC_ENCRYPTION_INFO
IPAs downloaded from the App Store have their main binary encrypted (cryptid 1). Static analysis of such a binary only sees headers and imports. For a full scan, analyse the IPA exported from Xcode (Ad Hoc / Development / Enterprise) or the archive before upload.

## Jailbreak detection and App Attest
Tags: MASVS-RESILIENCE-1, MASVS-RESILIENCE-2, jailbreak detection, DCAppAttestService, DeviceCheck, IOSSecuritySuite
Client-side jailbreak checks (Cydia paths, sandbox write tests, dyld image checks) raise attacker effort but are bypassable. App Attest (DCAppAttestService) lets your server verify that requests come from a genuine, unmodified instance of your app on a real device; verify assertions server-side for sensitive operations.

## Hardcoded credentials in iOS apps
Tags: MASVS-STORAGE-1, M1, CWE-798, hardcoded password, API key, Info.plist, GoogleService-Info.plist
Strings in the Mach-O binary (__cstring), Info.plist, JSON and plist resources are trivially extracted with `strings` or class-dump. Hardcoded admin passwords, comparison against fixed PINs, and paid-API keys must be removed; authenticate on the server. Keys designed to be public (GoogleService-Info.plist API_KEY) should be restricted by bundle ID in the provider console.
