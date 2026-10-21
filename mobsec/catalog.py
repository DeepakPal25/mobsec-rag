"""Rule catalog: metadata for every check, shared by binary and source scanners.

Each entry maps a rule id to title, severity, OWASP MASVS control, OWASP Mobile
Top 10 (2024) category, CWE, a retrieval query for the knowledge base, and a
short default fix (used when no LLM is configured).
"""
from __future__ import annotations

TOP10 = {
    "M1": "M1: Improper Credential Usage", "M2": "M2: Inadequate Supply Chain Security",
    "M3": "M3: Insecure Authentication/Authorization", "M4": "M4: Insufficient Input/Output Validation",
    "M5": "M5: Insecure Communication", "M6": "M6: Inadequate Privacy Controls",
    "M7": "M7: Insufficient Binary Protections", "M8": "M8: Security Misconfiguration",
    "M9": "M9: Insecure Data Storage", "M10": "M10: Insufficient Cryptography",
}

RULES: dict[str, dict] = {}


def R(rid, platform, sev, masvs, top, cwe, title, query, fix):
    RULES[rid] = dict(id=rid, platform=platform, severity=sev, masvs=masvs, top10=TOP10[top],
                      cwe=cwe, title=title, query=query, fix=fix)


A, I, X = "android", "ios", "any"

# ------------------------------------------------------------------ common
R("SEC-HARDCODED", X, "high", "MASVS-STORAGE-1", "M1", "CWE-798", "Hardcoded secret or API key",
  "hardcoded credentials API keys secrets in mobile app binary",
  "Remove the secret from the app, rotate it, and fetch short-lived tokens from your backend after authentication.")
R("SEC-PRIVATE-KEY", X, "high", "MASVS-CRYPTO-2", "M1", "CWE-321", "Private key or keystore bundled in the app",
  "private key embedded in app package key management",
  "Never ship private keys/keystores in the app. Generate keys on-device (Android Keystore / Secure Enclave) or keep them server-side.")
R("SEC-FIREBASE", X, "medium", "MASVS-NETWORK-1", "M8", "CWE-284", "Firebase Realtime Database URL found - verify security rules",
  "Firebase database misconfiguration open rules",
  "Confirm the database rules deny unauthenticated read/write (try GET <url>/.json). Lock rules to auth.uid.")
R("SEC-CLOUD-BUCKET", X, "info", "MASVS-NETWORK-1", "M8", "CWE-284", "Cloud storage bucket URL referenced",
  "cloud storage bucket public access S3",
  "Make sure the bucket is not publicly listable or writable; serve user content through signed URLs.")

# ------------------------------------------------------------------ Android: manifest / config
R("AND-DEBUGGABLE", A, "high", "MASVS-RESILIENCE-4", "M7", "CWE-489", "App is debuggable (android:debuggable=true)",
  "Android debuggable flag manifest jdwp debugging",
  "Remove android:debuggable from the manifest; let the build system set it only for debug builds.")
R("AND-ALLOW-BACKUP", A, "medium", "MASVS-STORAGE-2", "M9", "CWE-530", "App data can be backed up (allowBackup)",
  "Android allowBackup adb backup sensitive data fullBackupContent dataExtractionRules",
  "Set android:allowBackup=\"false\", or exclude sensitive files with dataExtractionRules / fullBackupContent.")
R("AND-CLEARTEXT", A, "high", "MASVS-NETWORK-1", "M5", "CWE-319", "Cleartext (HTTP) traffic permitted",
  "Android cleartext traffic usesCleartextTraffic network security config cleartextTrafficPermitted",
  "Set usesCleartextTraffic=\"false\" / cleartextTrafficPermitted=\"false\" and use HTTPS everywhere.")
R("AND-NSC-USER-CA", A, "medium", "MASVS-NETWORK-1", "M5", "CWE-295", "Network config trusts user-installed CA certificates",
  "Android network security config trust-anchors user certificates",
  "Remove <certificates src=\"user\"/> from base-config/domain-config; keep it only inside <debug-overrides>.")
R("AND-NSC-OVERRIDE-PINS", A, "medium", "MASVS-NETWORK-2", "M5", "CWE-295", "Network config lets custom CAs override pinning",
  "Android network security config overridePins pin-set",
  "Remove overridePins=\"true\" from release trust anchors.")
R("AND-EXPORTED-ACTIVITY", A, "medium", "MASVS-PLATFORM-1", "M8", "CWE-926", "Exported activity without permission",
  "Android exported activity intent access control",
  "Set android:exported=\"false\" unless other apps must open it; otherwise protect it with a signature permission and validate intent extras.")
R("AND-EXPORTED-SERVICE", A, "high", "MASVS-PLATFORM-1", "M8", "CWE-926", "Exported service without permission",
  "Android exported service binder access control",
  "Set android:exported=\"false\" or require a signature-level permission; check caller identity in onBind/onStartCommand.")
R("AND-EXPORTED-RECEIVER", A, "medium", "MASVS-PLATFORM-1", "M8", "CWE-926", "Exported broadcast receiver without permission",
  "Android exported broadcast receiver intent spoofing",
  "Set android:exported=\"false\", register receivers with RECEIVER_NOT_EXPORTED, or require a signature permission.")
R("AND-EXPORTED-PROVIDER", A, "high", "MASVS-PLATFORM-1", "M8", "CWE-926", "Exported content provider without permission",
  "Android exported content provider SQL injection path traversal permissions",
  "Set android:exported=\"false\" or add read/write signature permissions; use parameterised queries and canonical path checks.")
R("AND-PROVIDER-GRANT-URI", A, "low", "MASVS-PLATFORM-1", "M8", "CWE-266", "Content provider grants URI permissions",
  "Android grantUriPermissions FileProvider paths",
  "Restrict grant-uri-permission paths and FileProvider <paths> to specific folders (never root-path or '.').")
R("AND-WEAK-PERMISSION", A, "medium", "MASVS-PLATFORM-1", "M8", "CWE-276", "Custom permission with weak protectionLevel",
  "Android custom permission protectionLevel signature",
  "Use android:protectionLevel=\"signature\" for permissions that guard app components.")
R("AND-TEST-ONLY", A, "medium", "MASVS-CODE-2", "M8", "CWE-489", "APK marked testOnly",
  "Android testOnly build", "Build release APKs without android:testOnly.")
R("AND-OLD-MINSDK", A, "low", "MASVS-CODE-3", "M8", "CWE-1104", "Supports outdated Android versions (low minSdkVersion)",
  "Android minSdkVersion outdated platform security patches",
  "Raise minSdkVersion (23+ recommended) so the app does not run on unpatched OS versions.")
R("AND-OLD-TARGETSDK", A, "low", "MASVS-CODE-3", "M8", "CWE-1104", "Low targetSdkVersion disables newer platform protections",
  "Android targetSdkVersion security behavior changes",
  "Target the latest API level required by Google Play to inherit platform hardening.")
R("AND-SHARED-UID", A, "low", "MASVS-PLATFORM-1", "M8", "CWE-250", "Uses android:sharedUserId",
  "Android sharedUserId deprecated", "Remove sharedUserId; share data through explicit, permission-protected interfaces.")
R("AND-DEEPLINK", A, "low", "MASVS-PLATFORM-1", "M4", "CWE-939", "Deep links / custom schemes (verify input validation)",
  "Android deep link app links autoVerify custom scheme intent filter",
  "Prefer verified App Links (autoVerify) over custom schemes, and validate every parameter read from the URI.")
R("AND-TASK-HIJACK", A, "low", "MASVS-PLATFORM-3", "M8", "CWE-1021", "Activity task configuration allows task hijacking (StrandHogg)",
  "Android task hijacking taskAffinity launchMode singleTask StrandHogg",
  "Set android:taskAffinity=\"\" on the application/sensitive activities and avoid singleTask unless required.")
R("AND-DANGEROUS-PERMS", A, "info", "MASVS-PRIVACY-1", "M6", "CWE-250", "Dangerous / sensitive permissions requested",
  "Android dangerous permissions privacy data minimization",
  "Request only the permissions a feature needs, at the time it is used.")
R("AND-EXTERNAL-STORAGE", A, "medium", "MASVS-STORAGE-2", "M9", "CWE-922", "Uses shared external storage",
  "Android external storage sensitive data scoped storage",
  "Store sensitive data in internal storage (getFilesDir) or encrypt it; external storage is readable by other apps on older Android.")
R("AND-SIGN-V1-ONLY", A, "medium", "MASVS-CODE-2", "M7", "CWE-347", "Signed with v1 (JAR) scheme only - Janus vulnerability",
  "Android APK signature scheme v2 v3 Janus CVE-2017-13156",
  "Sign with APK Signature Scheme v2/v3 (default in modern build tools) and raise minSdk to 24+.")
R("AND-DEBUG-CERT", A, "high", "MASVS-CODE-2", "M7", "CWE-296", "Signed with the Android debug certificate",
  "Android debug signing certificate release build",
  "Sign release builds with your own release key (or Play App Signing).")

# ------------------------------------------------------------------ Android: code
R("AND-WEBVIEW-JSI", A, "high", "MASVS-PLATFORM-2", "M4", "CWE-749", "WebView exposes a JavaScript interface (addJavascriptInterface)",
  "Android WebView addJavascriptInterface remote code execution",
  "Only expose interfaces to trusted, HTTPS-only content; annotate methods with @JavascriptInterface and validate input; prefer WebMessageListener with origin allowlist.")
R("AND-WEBVIEW-FILE", A, "high", "MASVS-PLATFORM-2", "M4", "CWE-749", "WebView allows file access from file URLs",
  "Android WebView setAllowFileAccessFromFileURLs setAllowUniversalAccessFromFileURLs setAllowFileAccess",
  "Call setAllowFileAccess(false), setAllowFileAccessFromFileURLs(false), setAllowUniversalAccessFromFileURLs(false); load local content via WebViewAssetLoader.")
R("AND-WEBVIEW-JS", A, "low", "MASVS-PLATFORM-2", "M4", "CWE-79", "JavaScript enabled in WebView",
  "Android WebView setJavaScriptEnabled XSS untrusted content",
  "Enable JavaScript only for WebViews that load trusted HTTPS content you control.")
R("AND-WEBVIEW-DEBUG", A, "medium", "MASVS-RESILIENCE-4", "M7", "CWE-489", "WebView remote debugging enabled",
  "Android setWebContentsDebuggingEnabled", "Only enable WebView debugging in debug builds (BuildConfig.DEBUG).")
R("AND-WEBVIEW-SSL", A, "high", "MASVS-NETWORK-1", "M5", "CWE-295", "WebView ignores SSL errors (onReceivedSslError -> proceed)",
  "Android WebViewClient onReceivedSslError handler proceed",
  "Never call handler.proceed() in onReceivedSslError; call handler.cancel() (the default).")
R("AND-TLS-TRUST-ALL", A, "high", "MASVS-NETWORK-1", "M5", "CWE-295", "Custom TrustManager accepts all certificates",
  "Android X509TrustManager checkServerTrusted empty trust all certificates",
  "Remove the custom TrustManager and use the platform default; for pinning use Network Security Config <pin-set> or OkHttp CertificatePinner.")
R("AND-TLS-HOSTNAME", A, "high", "MASVS-NETWORK-1", "M5", "CWE-297", "Hostname verification disabled",
  "Android HostnameVerifier verify return true ALLOW_ALL_HOSTNAME_VERIFIER",
  "Use the default HostnameVerifier; never return true unconditionally.")
R("AND-TLS-INSECURE-FACTORY", A, "high", "MASVS-NETWORK-1", "M5", "CWE-295", "Insecure SSL socket factory",
  "Android SSLCertificateSocketFactory getInsecure", "Use the default SSLSocketFactory.")
R("AND-HTTP-URL", A, "medium", "MASVS-NETWORK-1", "M5", "CWE-319", "Cleartext http:// URL in code",
  "Android cleartext HTTP URL traffic", "Use https:// endpoints.")
R("AND-NO-PINNING", A, "info", "MASVS-NETWORK-2", "M5", "CWE-295", "No certificate pinning detected",
  "Android certificate pinning network security config pin-set OkHttp CertificatePinner",
  "For high-risk apps add pinning via Network Security Config <pin-set> (with a backup pin) or OkHttp CertificatePinner.")
R("AND-CRYPTO-ECB", A, "high", "MASVS-CRYPTO-1", "M10", "CWE-327", "Cipher uses ECB mode (or default 'AES' = ECB)",
  "Android Cipher getInstance AES ECB mode insecure", "Use \"AES/GCM/NoPadding\" with a random 12-byte IV per message.")
R("AND-CRYPTO-WEAK-CIPHER", A, "high", "MASVS-CRYPTO-1", "M10", "CWE-327", "Broken cipher (DES / 3DES / RC4 / Blowfish)",
  "Android weak cipher DES RC4 3DES", "Replace with AES-GCM or ChaCha20-Poly1305.")
R("AND-CRYPTO-RSA-NOPAD", A, "medium", "MASVS-CRYPTO-1", "M10", "CWE-780", "RSA without OAEP padding",
  "Android RSA ECB PKCS1Padding NoPadding OAEP", "Use \"RSA/ECB/OAEPWithSHA-256AndMGF1Padding\".")
R("AND-CRYPTO-CBC", A, "low", "MASVS-CRYPTO-1", "M10", "CWE-649", "CBC mode without authentication (verify a MAC is applied)",
  "Android AES CBC padding oracle authenticated encryption", "Prefer AES-GCM; if CBC is required, encrypt-then-MAC with HMAC-SHA256.")
R("AND-CRYPTO-WEAK-HASH", A, "medium", "MASVS-CRYPTO-1", "M10", "CWE-328", "Weak hash algorithm (MD5 / SHA-1)",
  "Android MessageDigest MD5 SHA-1 weak hash", "Use SHA-256+; for passwords use PBKDF2/Argon2 with a salt (ideally server-side).")
R("AND-CRYPTO-HARDCODED-KEY", A, "high", "MASVS-CRYPTO-2", "M10", "CWE-321", "Hardcoded encryption key or IV",
  "Android hardcoded key SecretKeySpec IvParameterSpec static IV Keystore",
  "Generate keys in the Android Keystore (KeyGenerator with KeyGenParameterSpec) and use a random IV per encryption.")
R("AND-CRYPTO-RANDOM", A, "low", "MASVS-CRYPTO-1", "M10", "CWE-330", "Insecure random number generator (java.util.Random)",
  "Android java.util.Random SecureRandom", "Use java.security.SecureRandom for tokens, keys, nonces and IDs.")
R("AND-CRYPTO-SEED", A, "medium", "MASVS-CRYPTO-1", "M10", "CWE-337", "SecureRandom seeded with a fixed value",
  "Android SecureRandom setSeed predictable", "Do not call setSeed(); let SecureRandom self-seed.")
R("AND-PREFS-SECRETS", A, "medium", "MASVS-STORAGE-1", "M9", "CWE-312", "Sensitive data stored in SharedPreferences",
  "Android SharedPreferences plaintext credentials storage EncryptedSharedPreferences",
  "Keep secrets in the Android Keystore or encrypt them (Jetpack Security / Tink) before storing.")
R("AND-WORLD-READABLE", A, "high", "MASVS-STORAGE-2", "M9", "CWE-276", "File/preferences created world-readable or world-writable",
  "Android MODE_WORLD_READABLE MODE_WORLD_WRITEABLE", "Use Context.MODE_PRIVATE.")
R("AND-SQLITE-PLAIN", A, "info", "MASVS-STORAGE-1", "M9", "CWE-312", "Unencrypted SQLite database",
  "Android SQLite database encryption SQLCipher Room sensitive data",
  "Do not store sensitive data in local DBs, or encrypt them (SQLCipher) with a Keystore-protected key.")
R("AND-SQLI", A, "medium", "MASVS-CODE-4", "M4", "CWE-89", "SQL query built from strings (possible SQL injection)",
  "Android SQL injection rawQuery execSQL selectionArgs", "Use parameterised queries (selectionArgs / ? placeholders / Room @Query).")
R("AND-LOGGING", A, "low", "MASVS-STORAGE-2", "M9", "CWE-532", "Logging in app code (check for sensitive data)",
  "Android Log sensitive data logcat leakage", "Strip logs from release builds (R8 -assumenosideeffects) and never log secrets or personal data.")
R("AND-CLIPBOARD", A, "low", "MASVS-STORAGE-2", "M6", "CWE-200", "Data copied to the clipboard",
  "Android clipboard sensitive data leakage", "Avoid copying secrets; on Android 13+ mark clips with ClipDescription.EXTRA_IS_SENSITIVE.")
R("AND-EXEC", A, "medium", "MASVS-CODE-4", "M4", "CWE-78", "Executes OS commands (Runtime.exec / ProcessBuilder)",
  "Android Runtime exec command injection", "Avoid shell commands; never pass user-controlled data to them.")
R("AND-DYNAMIC-CODE", A, "medium", "MASVS-CODE-4", "M2", "CWE-94", "Dynamic code loading (DexClassLoader)",
  "Android dynamic code loading DexClassLoader integrity", "Load code only from the APK, or verify signatures/integrity before loading.")
R("AND-IMPLICIT-BROADCAST", A, "low", "MASVS-PLATFORM-1", "M8", "CWE-927", "Broadcast sent without a receiver permission",
  "Android sendBroadcast implicit intent permission leakage", "Use explicit intents (setPackage) or sendBroadcast(intent, permission).")
R("AND-INTENT-REDIRECT", A, "medium", "MASVS-PLATFORM-1", "M4", "CWE-940", "Possible intent redirection (forwards an Intent received from extras)",
  "Android intent redirection getParcelableExtra startActivity", "Do not launch Intents taken from untrusted extras; validate component and flags, or use PendingIntents.")
R("AND-ZIP-SLIP", A, "medium", "MASVS-CODE-4", "M4", "CWE-22", "Zip extraction without path validation (Zip Slip)",
  "Android zip path traversal ZipEntry getName canonical path", "Resolve the canonical path of each entry and reject ones outside the target directory.")
R("AND-BIOMETRIC-NO-CRYPTO", A, "medium", "MASVS-AUTH-2", "M3", "CWE-287", "Biometric authentication without a CryptoObject (bypassable)",
  "Android BiometricPrompt CryptoObject event-bound authentication bypass",
  "Use BiometricPrompt.authenticate(promptInfo, CryptoObject) with a Keystore key that requires user authentication.")
R("AND-NO-FLAG-SECURE", A, "info", "MASVS-PLATFORM-3", "M6", "CWE-200", "FLAG_SECURE not used (screenshots / recents thumbnails allowed)",
  "Android FLAG_SECURE screenshots recent apps", "Set WindowManager.LayoutParams.FLAG_SECURE on screens that show sensitive data.")
R("AND-NO-ROOT-DETECTION", A, "info", "MASVS-RESILIENCE-1", "M7", "CWE-693", "No root detection or Play Integrity check found",
  "Android root detection Play Integrity API tampering", "For high-value apps add Play Integrity attestation verified on your server.")
R("AND-NOT-OBFUSCATED", A, "low", "MASVS-RESILIENCE-3", "M7", "CWE-693", "Code is not obfuscated (R8/ProGuard not enabled)",
  "Android obfuscation R8 ProGuard minifyEnabled reverse engineering", "Enable minifyEnabled true with R8 for release builds.")
R("AND-NATIVE-NX", A, "medium", "MASVS-CODE-4", "M7", "CWE-119", "Native library has executable stack (NX disabled)",
  "native library executable stack NX", "Rebuild with -z noexecstack (default in modern NDKs).")
R("AND-NATIVE-CANARY", A, "low", "MASVS-CODE-4", "M7", "CWE-121", "Native library built without stack canaries",
  "native library stack canary -fstack-protector", "Compile with -fstack-protector-strong.")
R("AND-NATIVE-RELRO", A, "low", "MASVS-CODE-4", "M7", "CWE-119", "Native library without full RELRO",
  "native library RELRO bind now", "Link with -Wl,-z,relro,-z,now.")
R("AND-NATIVE-UNSAFE", A, "info", "MASVS-CODE-4", "M7", "CWE-676", "Native code imports unsafe C functions",
  "native code unsafe functions strcpy sprintf buffer overflow", "Use bounded variants (strlcpy, snprintf) and enable FORTIFY_SOURCE.")
R("AND-TRACKERS", A, "info", "MASVS-PRIVACY-1", "M6", "CWE-359", "Third-party analytics / advertising SDKs",
  "third party SDK tracking privacy data collection", "Review data each SDK collects; disclose it in the Play Data safety form.")
R("AND-GRADLE-SECRETS", A, "high", "MASVS-STORAGE-1", "M1", "CWE-798", "Signing passwords or secrets in Gradle files",
  "hardcoded credentials build configuration", "Move secrets to environment variables or a local, git-ignored properties file / CI secrets.")
R("AND-PENDING-INTENT", A, "medium", "MASVS-PLATFORM-1", "M8", "CWE-927", "Mutable PendingIntent",
  "Android PendingIntent FLAG_MUTABLE implicit intent hijacking", "Use FLAG_IMMUTABLE and explicit Intents for PendingIntents.")

# ------------------------------------------------------------------ iOS: config
R("IOS-ATS-ARBITRARY", I, "high", "MASVS-NETWORK-1", "M5", "CWE-319", "App Transport Security disabled (NSAllowsArbitraryLoads)",
  "App Transport Security NSAllowsArbitraryLoads exception",
  "Remove NSAllowsArbitraryLoads; add narrow NSExceptionDomains only for hosts you cannot upgrade.")
R("IOS-ATS-EXCEPTION", I, "medium", "MASVS-NETWORK-1", "M5", "CWE-319", "ATS exception domain allows HTTP or old TLS",
  "App Transport Security NSExceptionAllowsInsecureHTTPLoads NSExceptionMinimumTLSVersion", "Remove the exception or limit it; require TLS 1.2+.")
R("IOS-ATS-WEB", I, "low", "MASVS-NETWORK-1", "M5", "CWE-319", "ATS relaxed for web content / media",
  "NSAllowsArbitraryLoadsInWebContent NSAllowsArbitraryLoadsForMedia", "Remove unless the app genuinely browses arbitrary web content.")
R("IOS-URL-SCHEME", I, "info", "MASVS-PLATFORM-1", "M4", "CWE-939", "Custom URL schemes registered (verify input validation)",
  "iOS custom URL scheme hijacking CFBundleURLTypes deep link validation",
  "Any app can claim the same scheme: validate every parameter and use Universal Links for auth callbacks.")
R("IOS-FILE-SHARING", I, "low", "MASVS-STORAGE-2", "M9", "CWE-200", "File sharing enabled (Documents exposed)",
  "iOS UIFileSharingEnabled Documents directory exposure", "Disable unless required; never keep sensitive files in Documents/.")
R("IOS-PERMISSIONS", I, "info", "MASVS-PRIVACY-1", "M6", "CWE-250", "Privacy-sensitive permissions requested",
  "iOS privacy permissions usage description data minimization", "Request only what features need; explain usage clearly.")
R("IOS-NO-PRIVACY-MANIFEST", I, "low", "MASVS-PRIVACY-1", "M6", "CWE-359", "Privacy manifest (PrivacyInfo.xcprivacy) missing",
  "iOS privacy manifest PrivacyInfo.xcprivacy required reason API", "Add PrivacyInfo.xcprivacy declaring data collection and required-reason APIs.")
R("IOS-OLD-MINOS", I, "low", "MASVS-CODE-3", "M8", "CWE-1104", "Supports outdated iOS versions",
  "iOS minimum deployment target outdated security updates", "Raise the deployment target to a supported iOS version (15+).")
R("IOS-GET-TASK-ALLOW", I, "high", "MASVS-RESILIENCE-4", "M7", "CWE-489", "get-task-allow entitlement enabled (debuggable build)",
  "iOS get-task-allow entitlement debuggable release build", "Ship with a distribution profile so get-task-allow is false.")
# ------------------------------------------------------------------ iOS: binary
R("IOS-NO-PIE", I, "medium", "MASVS-CODE-4", "M7", "CWE-119", "Binary not compiled as PIE (no full ASLR)",
  "iOS binary PIE ASLR", "Build with -fPIE / -pie (Xcode default).")
R("IOS-NO-CANARY", I, "low", "MASVS-CODE-4", "M7", "CWE-121", "Binary built without stack canaries",
  "iOS binary stack canary stack_chk_guard", "Compile with -fstack-protector-all.")
R("IOS-NO-ARC", I, "low", "MASVS-CODE-4", "M7", "CWE-416", "Objective-C code without ARC",
  "iOS Automatic Reference Counting ARC memory corruption", "Enable ARC (-fobjc-arc).")
R("IOS-STACK-EXEC", I, "high", "MASVS-CODE-4", "M7", "CWE-119", "Binary allows stack execution",
  "Mach-O MH_ALLOW_STACK_EXECUTION", "Remove the allow_stack_execute linker flag.")
R("IOS-NOT-STRIPPED", I, "low", "MASVS-RESILIENCE-3", "M7", "CWE-215", "Debug symbols not stripped",
  "iOS strip debug symbols reverse engineering", "Set STRIP_INSTALLED_PRODUCT=YES and DEPLOYMENT_POSTPROCESSING=YES for Release.")
R("IOS-ENCRYPTED", I, "info", "MASVS-RESILIENCE-3", "M7", "CWE-693", "Binary is FairPlay-encrypted (analysis limited)",
  "iOS FairPlay encrypted binary decrypt", "Scan an unencrypted build (Xcode archive / ad-hoc IPA) for full results.")
R("IOS-WEAK-HASH", I, "medium", "MASVS-CRYPTO-1", "M10", "CWE-328", "Weak hash algorithm (MD5 / SHA-1)",
  "iOS weak hash MD5 SHA1 CommonCrypto CryptoKit", "Use SHA-256+ (CryptoKit SHA256); use a KDF for passwords.")
R("IOS-WEAK-CIPHER", I, "high", "MASVS-CRYPTO-1", "M10", "CWE-327", "ECB mode or broken cipher (DES / 3DES / RC4)",
  "iOS insecure cipher ECB mode DES CommonCrypto", "Use AES-GCM via CryptoKit (AES.GCM.seal) or ChaChaPoly.")
R("IOS-HARDCODED-KEY", I, "high", "MASVS-CRYPTO-2", "M10", "CWE-321", "Hardcoded cryptographic key or IV",
  "iOS hardcoded encryption key management keychain secure enclave",
  "Generate keys at runtime (SymmetricKey(size:)) and keep them in the Keychain / Secure Enclave.")
R("IOS-WEAK-RANDOM", I, "low", "MASVS-CRYPTO-1", "M10", "CWE-338", "Insecure random number generator",
  "iOS secure random SecRandomCopyBytes", "Use SecRandomCopyBytes or SystemRandomNumberGenerator.")
R("IOS-UNSAFE-C", I, "info", "MASVS-CODE-4", "M7", "CWE-676", "Unsafe C functions imported (strcpy, sprintf, ...)",
  "iOS unsafe C functions buffer overflow", "Use bounded alternatives (strlcpy, snprintf).")
R("IOS-LOGGING", I, "low", "MASVS-STORAGE-2", "M9", "CWE-532", "NSLog / print logging (check for sensitive data)",
  "iOS logs sensitive data NSLog print", "Use os_log with privacy: .private and compile out debug logs.")
R("IOS-KEYCHAIN-WEAK", I, "medium", "MASVS-STORAGE-1", "M9", "CWE-311", "Weak Keychain accessibility class",
  "iOS keychain kSecAttrAccessible data protection class",
  "Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly (or WhenPasscodeSetThisDeviceOnly).")
R("IOS-FILE-PROTECTION-NONE", I, "medium", "MASVS-STORAGE-1", "M9", "CWE-311", "Files written without data protection (NSFileProtectionNone)",
  "iOS data protection NSFileProtectionComplete", "Use .completeFileProtection for sensitive files.")
R("IOS-USERDEFAULTS-SECRETS", I, "medium", "MASVS-STORAGE-1", "M9", "CWE-312", "Sensitive data stored in UserDefaults",
  "iOS UserDefaults plaintext sensitive data storage keychain", "Store secrets in the Keychain, not UserDefaults.")
R("IOS-UIWEBVIEW", I, "medium", "MASVS-PLATFORM-2", "M4", "CWE-749", "Deprecated UIWebView in use",
  "iOS UIWebView WKWebView security", "Migrate to WKWebView.")
R("IOS-WKWEBVIEW-BRIDGE", I, "medium", "MASVS-PLATFORM-2", "M4", "CWE-749", "WKWebView exposes native bridge / file access",
  "iOS WKWebView JavaScript bridge script message handler file access",
  "Validate message origin (frameInfo.securityOrigin) and body; never enable universal file access.")
R("IOS-TLS-BYPASS", I, "high", "MASVS-NETWORK-1", "M5", "CWE-295", "TLS certificate validation may be disabled",
  "iOS server trust evaluation certificate validation URLSession didReceive challenge",
  "Evaluate the server trust with SecTrustEvaluateWithError; never accept untrusted certificates.")
R("IOS-HTTP-URL", I, "medium", "MASVS-NETWORK-1", "M5", "CWE-319", "Cleartext http:// URL in app",
  "iOS cleartext HTTP traffic App Transport Security", "Use https:// endpoints only.")
R("IOS-NO-PINNING", I, "info", "MASVS-NETWORK-2", "M5", "CWE-295", "No certificate pinning detected",
  "iOS certificate pinning NSPinnedDomains TrustKit", "For high-risk apps add pinning via NSPinnedDomains or a vetted library.")
R("IOS-BIOMETRIC-EVENT", I, "medium", "MASVS-AUTH-2", "M3", "CWE-287", "Biometric auth result used as a boolean (bypassable)",
  "iOS LocalAuthentication evaluatePolicy bypass keychain access control biometry",
  "Protect a Keychain item with SecAccessControl(.biometryCurrentSet) instead of trusting evaluatePolicy's bool.")
R("IOS-PASTEBOARD", I, "low", "MASVS-STORAGE-2", "M6", "CWE-200", "General pasteboard used",
  "iOS UIPasteboard sensitive data clipboard", "Avoid copying secrets; use localOnly + expirationDate options.")
R("IOS-SQLI", I, "medium", "MASVS-CODE-4", "M4", "CWE-89", "SQL built from format strings (possible SQL injection)",
  "SQL injection sqlite3 parameterized queries sqlite3_bind", "Use prepared statements with sqlite3_bind_*.")
R("IOS-DB-PLAIN", I, "info", "MASVS-STORAGE-1", "M9", "CWE-312", "Local database (SQLite / Realm / Core Data) - verify encryption",
  "iOS local database encryption Realm SQLite Core Data", "Encrypt DBs holding sensitive data (SQLCipher / Realm encryptionKey).")
R("IOS-NO-JB-DETECTION", I, "info", "MASVS-RESILIENCE-1", "M7", "CWE-693", "No jailbreak detection or App Attest found",
  "iOS jailbreak detection App Attest DeviceCheck", "For high-value apps add App Attest verified on your server.")
R("IOS-BUNDLED-HEADERS", I, "info", "MASVS-RESILIENCE-3", "M7", "CWE-540", "Source/header or debug files shipped inside the app bundle",
  "iOS app bundle leftover files", "Exclude headers, source and test files from the Copy Bundle Resources phase.")
R("IOS-SDKS", I, "info", "MASVS-PRIVACY-1", "M6", "CWE-359", "Embedded third-party frameworks",
  "third party SDK supply chain privacy", "Keep SDKs updated and confirm each ships a privacy manifest.")
R("IOS-DEBUG-FLAGS", I, "low", "MASVS-RESILIENCE-4", "M7", "CWE-489", "Debug / test flags left in code",
  "iOS debugging code debug flags release build", "Gate debug code behind #if DEBUG.")
R("IOS-URL-HANDLER", I, "info", "MASVS-PLATFORM-1", "M4", "CWE-20", "URL / deep link handler (verify input validation)",
  "iOS custom URL scheme deep link validation universal links", "Validate host/path/params of incoming URLs.")


# ------------------------------------------------------------------ hardening / anti-reverse-engineering (MASVS-RESILIENCE)
# Defaults are low/info: these are defence-in-depth controls. `--profile high-risk` (banking, health,
# payments, DRM, games with economies) raises them to medium, matching MASVS-R expectations.
R("AND-NO-ANTI-DEBUG", A, "low", "MASVS-RESILIENCE-4", "M7", "CWE-693", "No anti-debugging checks",
  "Android anti-debugging isDebuggerConnected TracerPid JDWP detection",
  "Detect debuggers at runtime (Debug.isDebuggerConnected, TracerPid in /proc/self/status) and react server-side.")
R("AND-NO-HOOK-DETECTION", A, "low", "MASVS-RESILIENCE-4", "M7", "CWE-693", "No Frida / Xposed hooking detection",
  "Android Frida Xposed hooking detection instrumentation /proc/self/maps",
  "Detect instrumentation (Frida server/gadget, Xposed/LSPosed, Substrate) or use a RASP SDK; enforce via attestation.")
R("AND-NO-EMULATOR-DETECTION", A, "info", "MASVS-RESILIENCE-1", "M7", "CWE-693", "No emulator detection",
  "Android emulator detection goldfish ranchu Build properties",
  "Detect emulators (Build.FINGERPRINT/HARDWARE, qemu properties) for flows that must run on real devices.")
R("AND-NO-TAMPER-CHECK", A, "low", "MASVS-RESILIENCE-2", "M7", "CWE-354", "No app signature / integrity (anti-tampering) check",
  "Android anti-tampering signature verification repackaging getPackageInfo signingInfo installer",
  "Verify the signing certificate and installer at runtime, and verify Play Integrity verdicts (appIntegrity) on your server.")
R("AND-NO-ATTESTATION", A, "info", "MASVS-RESILIENCE-2", "M7", "CWE-693", "No Play Integrity attestation",
  "Play Integrity API attestation server verification", "Request Play Integrity tokens for sensitive actions and verify them server-side.")
R("AND-NO-TAPJACKING-PROTECTION", A, "low", "MASVS-PLATFORM-3", "M8", "CWE-1021", "No tapjacking / overlay protection",
  "Android tapjacking overlay filterTouchesWhenObscured setHideOverlayWindows",
  "Set filterTouchesWhenObscured on sensitive views and call window.setHideOverlayWindows(true) (Android 12+).")
R("AND-DEBUG-INFO-RETAINED", A, "low", "MASVS-RESILIENCE-3", "M7", "CWE-215", "Source file names / line numbers kept in DEX",
  "R8 renamesourcefileattribute keepattributes SourceFile LineNumberTable",
  "Add -renamesourcefileattribute SourceFile to proguard-rules.pro and upload mapping.txt for crash de-obfuscation.")
R("AND-NO-STRING-ENCRYPTION", A, "info", "MASVS-RESILIENCE-3", "M7", "CWE-312", "Sensitive strings are stored in plaintext in the app",
  "string encryption obfuscation DexGuard StringFog plaintext strings reverse engineering",
  "Move secrets server-side; for high-risk apps encrypt sensitive constants with a commercial protector or string-encryption plugin.")
R("AND-NATIVE-NOT-STRIPPED", A, "low", "MASVS-RESILIENCE-3", "M7", "CWE-215", "App native library not stripped (symbols present)",
  "native library strip symbols visibility hidden JNI", "Strip release .so files and build with -fvisibility=hidden; register JNI methods dynamically.")
R("AND-PACKED", A, "info", "MASVS-RESILIENCE-3", "M7", "CWE-693", "App is packed / protected by a commercial protector",
  "Android packer protector DexGuard Jiagu Bangcle", "Analysis of protected code is limited; scan the unprotected build as well.")
R("IOS-NOT-OBFUSCATED", I, "low", "MASVS-RESILIENCE-3", "M7", "CWE-693", "Class and method names are not obfuscated",
  "iOS obfuscation Swift Objective-C class names iXGuard SwiftShield reverse engineering",
  "For high-risk apps use an obfuscator (e.g. iXGuard, obfuscator-llvm) and keep business logic server-side.")
R("IOS-NO-ANTI-DEBUG", I, "low", "MASVS-RESILIENCE-4", "M7", "CWE-693", "No anti-debugging checks",
  "iOS anti-debugging ptrace PT_DENY_ATTACH sysctl P_TRACED", "Detect debuggers (sysctl P_TRACED) and deny attach (ptrace PT_DENY_ATTACH) in release builds.")
R("IOS-NO-HOOK-DETECTION", I, "low", "MASVS-RESILIENCE-4", "M7", "CWE-693", "No Frida / Substrate hooking detection",
  "iOS Frida detection dyld images Substrate hooking", "Detect injected dylibs (dyld image list), Frida ports and symbols, or use a RASP SDK.")
R("IOS-NO-TAMPER-CHECK", I, "low", "MASVS-RESILIENCE-2", "M7", "CWE-354", "No anti-tampering / re-signing check",
  "iOS anti-tampering re-signing embedded.mobileprovision code signature App Attest",
  "Check for re-signing (team ID, provisioning profile) and verify App Attest assertions on your server.")
R("IOS-NO-ATTESTATION", I, "info", "MASVS-RESILIENCE-2", "M7", "CWE-693", "No App Attest / DeviceCheck",
  "iOS App Attest DCAppAttestService DeviceCheck server verification", "Use DCAppAttestService and verify attestations server-side.")
R("IOS-NO-SCREEN-PROTECTION", I, "info", "MASVS-PLATFORM-3", "M6", "CWE-200", "No screen recording / screenshot protection",
  "iOS screen capture isCaptured screenshot app switcher snapshot", "Hide sensitive content when UIScreen.isCaptured is true and when the app resigns active.")

# ------------------------------------------------------------------ cross-platform (Flutter / React Native / JS)
R("XP-TLS-BYPASS", X, "high", "MASVS-NETWORK-1", "M5", "CWE-295", "TLS certificate validation disabled (Flutter / JS)",
  "certificate validation disabled badCertificateCallback rejectUnauthorized",
  "Remove badCertificateCallback / rejectUnauthorized:false; use pinning packages if needed.")
R("XP-INSECURE-STORAGE", X, "medium", "MASVS-STORAGE-1", "M9", "CWE-312", "Secret stored in plain key-value storage (AsyncStorage / SharedPreferences)",
  "React Native AsyncStorage Flutter shared_preferences sensitive data secure storage",
  "Use flutter_secure_storage / react-native-keychain (Keychain / Keystore backed) for tokens and credentials.")
R("XP-WEBVIEW", X, "medium", "MASVS-PLATFORM-2", "M4", "CWE-749", "Insecure WebView configuration (cross-platform)",
  "React Native WebView originWhitelist allowFileAccess JavaScript bridge",
  "Restrict originWhitelist to your domains, disable file access, and validate messages from the page.")
R("XP-HTTP-URL", X, "medium", "MASVS-NETWORK-1", "M5", "CWE-319", "Cleartext http:// URL (cross-platform code)",
  "cleartext HTTP URL mobile", "Use https:// endpoints.")
R("XP-LOGGING", X, "low", "MASVS-STORAGE-2", "M9", "CWE-532", "Sensitive data logged (cross-platform code)",
  "logging sensitive data console.log debugPrint", "Remove logging of secrets; strip logs from release builds.")
R("XP-EVAL", X, "medium", "MASVS-CODE-4", "M4", "CWE-95", "Dynamic code evaluation (eval / new Function)",
  "JavaScript eval code injection", "Avoid eval/new Function on any data that can be influenced externally.")

SEV_ORDER = ["high", "medium", "low", "info"]
SEV_WEIGHT = {"high": 10, "medium": 4, "low": 1, "info": 0}


def downgrade(sev: str) -> str:
    i = SEV_ORDER.index(sev)
    return SEV_ORDER[min(i + 1, len(SEV_ORDER) - 1)]
