# Rules

125 checks. Severities are defaults; `--profile high-risk` raises missing hardening controls to medium, and the LLM step may adjust severities per app.

## Android

| ID | Severity | MASVS | Top 10 | CWE | Check |
|---|---|---|---|---|---|
| `AND-CLEARTEXT` | high | MASVS-NETWORK-1 | M5 | CWE-319 | Cleartext (HTTP) traffic permitted |
| `AND-CRYPTO-ECB` | high | MASVS-CRYPTO-1 | M10 | CWE-327 | Cipher uses ECB mode (or default 'AES' = ECB) |
| `AND-CRYPTO-HARDCODED-KEY` | high | MASVS-CRYPTO-2 | M10 | CWE-321 | Hardcoded encryption key or IV |
| `AND-CRYPTO-WEAK-CIPHER` | high | MASVS-CRYPTO-1 | M10 | CWE-327 | Broken cipher (DES / 3DES / RC4 / Blowfish) |
| `AND-DEBUG-CERT` | high | MASVS-CODE-2 | M7 | CWE-296 | Signed with the Android debug certificate |
| `AND-DEBUGGABLE` | high | MASVS-RESILIENCE-4 | M7 | CWE-489 | App is debuggable (android:debuggable=true) |
| `AND-EXPORTED-PROVIDER` | high | MASVS-PLATFORM-1 | M8 | CWE-926 | Exported content provider without permission |
| `AND-EXPORTED-SERVICE` | high | MASVS-PLATFORM-1 | M8 | CWE-926 | Exported service without permission |
| `AND-GRADLE-SECRETS` | high | MASVS-STORAGE-1 | M1 | CWE-798 | Signing passwords or secrets in Gradle files |
| `AND-TLS-HOSTNAME` | high | MASVS-NETWORK-1 | M5 | CWE-297 | Hostname verification disabled |
| `AND-TLS-INSECURE-FACTORY` | high | MASVS-NETWORK-1 | M5 | CWE-295 | Insecure SSL socket factory |
| `AND-TLS-TRUST-ALL` | high | MASVS-NETWORK-1 | M5 | CWE-295 | Custom TrustManager accepts all certificates |
| `AND-WEBVIEW-FILE` | high | MASVS-PLATFORM-2 | M4 | CWE-749 | WebView allows file access from file URLs |
| `AND-WEBVIEW-JSI` | high | MASVS-PLATFORM-2 | M4 | CWE-749 | WebView exposes a JavaScript interface (addJavascriptInterface) |
| `AND-WEBVIEW-SSL` | high | MASVS-NETWORK-1 | M5 | CWE-295 | WebView ignores SSL errors (onReceivedSslError -> proceed) |
| `AND-WORLD-READABLE` | high | MASVS-STORAGE-2 | M9 | CWE-276 | File/preferences created world-readable or world-writable |
| `AND-ALLOW-BACKUP` | medium | MASVS-STORAGE-2 | M9 | CWE-530 | App data can be backed up (allowBackup) |
| `AND-BIOMETRIC-NO-CRYPTO` | medium | MASVS-AUTH-2 | M3 | CWE-287 | Biometric authentication without a CryptoObject (bypassable) |
| `AND-CRYPTO-RSA-NOPAD` | medium | MASVS-CRYPTO-1 | M10 | CWE-780 | RSA without OAEP padding |
| `AND-CRYPTO-SEED` | medium | MASVS-CRYPTO-1 | M10 | CWE-337 | SecureRandom seeded with a fixed value |
| `AND-CRYPTO-WEAK-HASH` | medium | MASVS-CRYPTO-1 | M10 | CWE-328 | Weak hash algorithm (MD5 / SHA-1) |
| `AND-DYNAMIC-CODE` | medium | MASVS-CODE-4 | M2 | CWE-94 | Dynamic code loading (DexClassLoader) |
| `AND-EXEC` | medium | MASVS-CODE-4 | M4 | CWE-78 | Executes OS commands (Runtime.exec / ProcessBuilder) |
| `AND-EXPORTED-ACTIVITY` | medium | MASVS-PLATFORM-1 | M8 | CWE-926 | Exported activity without permission |
| `AND-EXPORTED-RECEIVER` | medium | MASVS-PLATFORM-1 | M8 | CWE-926 | Exported broadcast receiver without permission |
| `AND-EXTERNAL-STORAGE` | medium | MASVS-STORAGE-2 | M9 | CWE-922 | Uses shared external storage |
| `AND-HTTP-URL` | medium | MASVS-NETWORK-1 | M5 | CWE-319 | Cleartext http:// URL in code |
| `AND-INTENT-REDIRECT` | medium | MASVS-PLATFORM-1 | M4 | CWE-940 | Possible intent redirection (forwards an Intent received from extras) |
| `AND-NATIVE-NX` | medium | MASVS-CODE-4 | M7 | CWE-119 | Native library has executable stack (NX disabled) |
| `AND-NSC-OVERRIDE-PINS` | medium | MASVS-NETWORK-2 | M5 | CWE-295 | Network config lets custom CAs override pinning |
| `AND-NSC-USER-CA` | medium | MASVS-NETWORK-1 | M5 | CWE-295 | Network config trusts user-installed CA certificates |
| `AND-PENDING-INTENT` | medium | MASVS-PLATFORM-1 | M8 | CWE-927 | Mutable PendingIntent |
| `AND-PREFS-SECRETS` | medium | MASVS-STORAGE-1 | M9 | CWE-312 | Sensitive data stored in SharedPreferences |
| `AND-SIGN-V1-ONLY` | medium | MASVS-CODE-2 | M7 | CWE-347 | Signed with v1 (JAR) scheme only - Janus vulnerability |
| `AND-SQLI` | medium | MASVS-CODE-4 | M4 | CWE-89 | SQL query built from strings (possible SQL injection) |
| `AND-TEST-ONLY` | medium | MASVS-CODE-2 | M8 | CWE-489 | APK marked testOnly |
| `AND-WEAK-PERMISSION` | medium | MASVS-PLATFORM-1 | M8 | CWE-276 | Custom permission with weak protectionLevel |
| `AND-WEBVIEW-DEBUG` | medium | MASVS-RESILIENCE-4 | M7 | CWE-489 | WebView remote debugging enabled |
| `AND-ZIP-SLIP` | medium | MASVS-CODE-4 | M4 | CWE-22 | Zip extraction without path validation (Zip Slip) |
| `AND-CLIPBOARD` | low | MASVS-STORAGE-2 | M6 | CWE-200 | Data copied to the clipboard |
| `AND-CRYPTO-CBC` | low | MASVS-CRYPTO-1 | M10 | CWE-649 | CBC mode without authentication (verify a MAC is applied) |
| `AND-CRYPTO-RANDOM` | low | MASVS-CRYPTO-1 | M10 | CWE-330 | Insecure random number generator (java.util.Random) |
| `AND-DEBUG-INFO-RETAINED` | low | MASVS-RESILIENCE-3 | M7 | CWE-215 | Source file names / line numbers kept in DEX |
| `AND-DEEPLINK` | low | MASVS-PLATFORM-1 | M4 | CWE-939 | Deep links / custom schemes (verify input validation) |
| `AND-IMPLICIT-BROADCAST` | low | MASVS-PLATFORM-1 | M8 | CWE-927 | Broadcast sent without a receiver permission |
| `AND-LOGGING` | low | MASVS-STORAGE-2 | M9 | CWE-532 | Logging in app code (check for sensitive data) |
| `AND-NATIVE-CANARY` | low | MASVS-CODE-4 | M7 | CWE-121 | Native library built without stack canaries |
| `AND-NATIVE-NOT-STRIPPED` | low | MASVS-RESILIENCE-3 | M7 | CWE-215 | App native library not stripped (symbols present) |
| `AND-NATIVE-RELRO` | low | MASVS-CODE-4 | M7 | CWE-119 | Native library without full RELRO |
| `AND-NO-ANTI-DEBUG` | low | MASVS-RESILIENCE-4 | M7 | CWE-693 | No anti-debugging checks |
| `AND-NO-HOOK-DETECTION` | low | MASVS-RESILIENCE-4 | M7 | CWE-693 | No Frida / Xposed hooking detection |
| `AND-NO-TAMPER-CHECK` | low | MASVS-RESILIENCE-2 | M7 | CWE-354 | No app signature / integrity (anti-tampering) check |
| `AND-NO-TAPJACKING-PROTECTION` | low | MASVS-PLATFORM-3 | M8 | CWE-1021 | No tapjacking / overlay protection |
| `AND-NOT-OBFUSCATED` | low | MASVS-RESILIENCE-3 | M7 | CWE-693 | Code is not obfuscated (R8/ProGuard not enabled) |
| `AND-OLD-MINSDK` | low | MASVS-CODE-3 | M8 | CWE-1104 | Supports outdated Android versions (low minSdkVersion) |
| `AND-OLD-TARGETSDK` | low | MASVS-CODE-3 | M8 | CWE-1104 | Low targetSdkVersion disables newer platform protections |
| `AND-PROVIDER-GRANT-URI` | low | MASVS-PLATFORM-1 | M8 | CWE-266 | Content provider grants URI permissions |
| `AND-SHARED-UID` | low | MASVS-PLATFORM-1 | M8 | CWE-250 | Uses android:sharedUserId |
| `AND-TASK-HIJACK` | low | MASVS-PLATFORM-3 | M8 | CWE-1021 | Activity task configuration allows task hijacking (StrandHogg) |
| `AND-WEBVIEW-JS` | low | MASVS-PLATFORM-2 | M4 | CWE-79 | JavaScript enabled in WebView |
| `AND-DANGEROUS-PERMS` | info | MASVS-PRIVACY-1 | M6 | CWE-250 | Dangerous / sensitive permissions requested |
| `AND-NATIVE-UNSAFE` | info | MASVS-CODE-4 | M7 | CWE-676 | Native code imports unsafe C functions |
| `AND-NO-ATTESTATION` | info | MASVS-RESILIENCE-2 | M7 | CWE-693 | No Play Integrity attestation |
| `AND-NO-EMULATOR-DETECTION` | info | MASVS-RESILIENCE-1 | M7 | CWE-693 | No emulator detection |
| `AND-NO-FLAG-SECURE` | info | MASVS-PLATFORM-3 | M6 | CWE-200 | FLAG_SECURE not used (screenshots / recents thumbnails allowed) |
| `AND-NO-PINNING` | info | MASVS-NETWORK-2 | M5 | CWE-295 | No certificate pinning detected |
| `AND-NO-ROOT-DETECTION` | info | MASVS-RESILIENCE-1 | M7 | CWE-693 | No root detection or Play Integrity check found |
| `AND-NO-STRING-ENCRYPTION` | info | MASVS-RESILIENCE-3 | M7 | CWE-312 | Sensitive strings are stored in plaintext in the app |
| `AND-PACKED` | info | MASVS-RESILIENCE-3 | M7 | CWE-693 | App is packed / protected by a commercial protector |
| `AND-SQLITE-PLAIN` | info | MASVS-STORAGE-1 | M9 | CWE-312 | Unencrypted SQLite database |
| `AND-TRACKERS` | info | MASVS-PRIVACY-1 | M6 | CWE-359 | Third-party analytics / advertising SDKs |

## iOS

| ID | Severity | MASVS | Top 10 | CWE | Check |
|---|---|---|---|---|---|
| `IOS-ATS-ARBITRARY` | high | MASVS-NETWORK-1 | M5 | CWE-319 | App Transport Security disabled (NSAllowsArbitraryLoads) |
| `IOS-GET-TASK-ALLOW` | high | MASVS-RESILIENCE-4 | M7 | CWE-489 | get-task-allow entitlement enabled (debuggable build) |
| `IOS-HARDCODED-KEY` | high | MASVS-CRYPTO-2 | M10 | CWE-321 | Hardcoded cryptographic key or IV |
| `IOS-STACK-EXEC` | high | MASVS-CODE-4 | M7 | CWE-119 | Binary allows stack execution |
| `IOS-TLS-BYPASS` | high | MASVS-NETWORK-1 | M5 | CWE-295 | TLS certificate validation may be disabled |
| `IOS-WEAK-CIPHER` | high | MASVS-CRYPTO-1 | M10 | CWE-327 | ECB mode or broken cipher (DES / 3DES / RC4) |
| `IOS-ATS-EXCEPTION` | medium | MASVS-NETWORK-1 | M5 | CWE-319 | ATS exception domain allows HTTP or old TLS |
| `IOS-BIOMETRIC-EVENT` | medium | MASVS-AUTH-2 | M3 | CWE-287 | Biometric auth result used as a boolean (bypassable) |
| `IOS-FILE-PROTECTION-NONE` | medium | MASVS-STORAGE-1 | M9 | CWE-311 | Files written without data protection (NSFileProtectionNone) |
| `IOS-HTTP-URL` | medium | MASVS-NETWORK-1 | M5 | CWE-319 | Cleartext http:// URL in app |
| `IOS-KEYCHAIN-WEAK` | medium | MASVS-STORAGE-1 | M9 | CWE-311 | Weak Keychain accessibility class |
| `IOS-NO-PIE` | medium | MASVS-CODE-4 | M7 | CWE-119 | Binary not compiled as PIE (no full ASLR) |
| `IOS-SQLI` | medium | MASVS-CODE-4 | M4 | CWE-89 | SQL built from format strings (possible SQL injection) |
| `IOS-UIWEBVIEW` | medium | MASVS-PLATFORM-2 | M4 | CWE-749 | Deprecated UIWebView in use |
| `IOS-USERDEFAULTS-SECRETS` | medium | MASVS-STORAGE-1 | M9 | CWE-312 | Sensitive data stored in UserDefaults |
| `IOS-WEAK-HASH` | medium | MASVS-CRYPTO-1 | M10 | CWE-328 | Weak hash algorithm (MD5 / SHA-1) |
| `IOS-WKWEBVIEW-BRIDGE` | medium | MASVS-PLATFORM-2 | M4 | CWE-749 | WKWebView exposes native bridge / file access |
| `IOS-ATS-WEB` | low | MASVS-NETWORK-1 | M5 | CWE-319 | ATS relaxed for web content / media |
| `IOS-DEBUG-FLAGS` | low | MASVS-RESILIENCE-4 | M7 | CWE-489 | Debug / test flags left in code |
| `IOS-FILE-SHARING` | low | MASVS-STORAGE-2 | M9 | CWE-200 | File sharing enabled (Documents exposed) |
| `IOS-LOGGING` | low | MASVS-STORAGE-2 | M9 | CWE-532 | NSLog / print logging (check for sensitive data) |
| `IOS-NO-ANTI-DEBUG` | low | MASVS-RESILIENCE-4 | M7 | CWE-693 | No anti-debugging checks |
| `IOS-NO-ARC` | low | MASVS-CODE-4 | M7 | CWE-416 | Objective-C code without ARC |
| `IOS-NO-CANARY` | low | MASVS-CODE-4 | M7 | CWE-121 | Binary built without stack canaries |
| `IOS-NO-HOOK-DETECTION` | low | MASVS-RESILIENCE-4 | M7 | CWE-693 | No Frida / Substrate hooking detection |
| `IOS-NO-PRIVACY-MANIFEST` | low | MASVS-PRIVACY-1 | M6 | CWE-359 | Privacy manifest (PrivacyInfo.xcprivacy) missing |
| `IOS-NO-TAMPER-CHECK` | low | MASVS-RESILIENCE-2 | M7 | CWE-354 | No anti-tampering / re-signing check |
| `IOS-NOT-OBFUSCATED` | low | MASVS-RESILIENCE-3 | M7 | CWE-693 | Class and method names are not obfuscated |
| `IOS-NOT-STRIPPED` | low | MASVS-RESILIENCE-3 | M7 | CWE-215 | Debug symbols not stripped |
| `IOS-OLD-MINOS` | low | MASVS-CODE-3 | M8 | CWE-1104 | Supports outdated iOS versions |
| `IOS-PASTEBOARD` | low | MASVS-STORAGE-2 | M6 | CWE-200 | General pasteboard used |
| `IOS-WEAK-RANDOM` | low | MASVS-CRYPTO-1 | M10 | CWE-338 | Insecure random number generator |
| `IOS-BUNDLED-HEADERS` | info | MASVS-RESILIENCE-3 | M7 | CWE-540 | Source/header or debug files shipped inside the app bundle |
| `IOS-DB-PLAIN` | info | MASVS-STORAGE-1 | M9 | CWE-312 | Local database (SQLite / Realm / Core Data) - verify encryption |
| `IOS-ENCRYPTED` | info | MASVS-RESILIENCE-3 | M7 | CWE-693 | Binary is FairPlay-encrypted (analysis limited) |
| `IOS-NO-ATTESTATION` | info | MASVS-RESILIENCE-2 | M7 | CWE-693 | No App Attest / DeviceCheck |
| `IOS-NO-JB-DETECTION` | info | MASVS-RESILIENCE-1 | M7 | CWE-693 | No jailbreak detection or App Attest found |
| `IOS-NO-PINNING` | info | MASVS-NETWORK-2 | M5 | CWE-295 | No certificate pinning detected |
| `IOS-NO-SCREEN-PROTECTION` | info | MASVS-PLATFORM-3 | M6 | CWE-200 | No screen recording / screenshot protection |
| `IOS-PERMISSIONS` | info | MASVS-PRIVACY-1 | M6 | CWE-250 | Privacy-sensitive permissions requested |
| `IOS-SDKS` | info | MASVS-PRIVACY-1 | M6 | CWE-359 | Embedded third-party frameworks |
| `IOS-UNSAFE-C` | info | MASVS-CODE-4 | M7 | CWE-676 | Unsafe C functions imported (strcpy, sprintf, ...) |
| `IOS-URL-HANDLER` | info | MASVS-PLATFORM-1 | M4 | CWE-20 | URL / deep link handler (verify input validation) |
| `IOS-URL-SCHEME` | info | MASVS-PLATFORM-1 | M4 | CWE-939 | Custom URL schemes registered (verify input validation) |

## Common (all platforms)

| ID | Severity | MASVS | Top 10 | CWE | Check |
|---|---|---|---|---|---|
| `SEC-HARDCODED` | high | MASVS-STORAGE-1 | M1 | CWE-798 | Hardcoded secret or API key |
| `SEC-PRIVATE-KEY` | high | MASVS-CRYPTO-2 | M1 | CWE-321 | Private key or keystore bundled in the app |
| `XP-TLS-BYPASS` | high | MASVS-NETWORK-1 | M5 | CWE-295 | TLS certificate validation disabled (Flutter / JS) |
| `SEC-FIREBASE` | medium | MASVS-NETWORK-1 | M8 | CWE-284 | Firebase Realtime Database URL found - verify security rules |
| `XP-EVAL` | medium | MASVS-CODE-4 | M4 | CWE-95 | Dynamic code evaluation (eval / new Function) |
| `XP-HTTP-URL` | medium | MASVS-NETWORK-1 | M5 | CWE-319 | Cleartext http:// URL (cross-platform code) |
| `XP-INSECURE-STORAGE` | medium | MASVS-STORAGE-1 | M9 | CWE-312 | Secret stored in plain key-value storage (AsyncStorage / SharedPreferences) |
| `XP-WEBVIEW` | medium | MASVS-PLATFORM-2 | M4 | CWE-749 | Insecure WebView configuration (cross-platform) |
| `XP-LOGGING` | low | MASVS-STORAGE-2 | M9 | CWE-532 | Sensitive data logged (cross-platform code) |
| `SEC-CLOUD-BUCKET` | info | MASVS-NETWORK-1 | M8 | CWE-284 | Cloud storage bucket URL referenced |
