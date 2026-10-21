"""Regex rules for source code. Each rule: catalog id, regexes, file extensions,
optional `requires` (file must also match) / `unless` (file must not match),
`line_unless` (skip a hit when the line matches), and optional severity override.
"""
from __future__ import annotations

JAVA_KT = (".java", ".kt")
SWIFT_OBJC = (".swift", ".m", ".mm", ".h")
XP = (".dart", ".js", ".jsx", ".ts", ".tsx")
SECRET = r"(?i:password|passwd|pwd|token|secret|apikey|api_key|access_key|auth|session|pin\b|otp|credit|cvv|ssn)"
CRYPTO_NAME = r"\w*(?:aes|enc|encryption|crypt|cipher|secret|private|hmac|signing|master)_?(?:key|iv|salt)\w*|key|iv|salt|_?(?:aes|secret|crypto)Key"
NOT_LOCAL_URL = r"(?!localhost|127\.0\.0\.1|10\.0\.2\.2|0\.0\.0\.0|schemas\.|www\.w3\.org|ns\.adobe\.com|www\.apple\.com/DTDs|xml\.org|json-schema\.org|example\.com)"


def r(rule, patterns, exts, severity=None, requires=None, unless=None, line_unless=None, multiline=False):
    return dict(rule=rule, patterns=patterns, exts=exts, severity=severity, requires=requires, unless=unless,
                line_unless=line_unless, multiline=multiline)


ANDROID = [
    r("AND-WEBVIEW-JSI", [r"\.addJavascriptInterface\s*\("], JAVA_KT),
    r("AND-WEBVIEW-FILE", [r"setAllow(FileAccessFromFileURLs|UniversalAccessFromFileURLs)\s*\(\s*true",
                           r"allow(FileAccessFromFileURLs|UniversalAccessFromFileURLs)\s*=\s*true"], JAVA_KT),
    r("AND-WEBVIEW-FILE", [r"setAllowFileAccess\s*\(\s*true", r"\ballowFileAccess\s*=\s*true"], JAVA_KT, severity="medium"),
    r("AND-WEBVIEW-JS", [r"setJavaScriptEnabled\s*\(\s*true", r"javaScriptEnabled\s*=\s*true"], JAVA_KT),
    r("AND-WEBVIEW-DEBUG", [r"setWebContentsDebuggingEnabled\s*\(\s*true"], JAVA_KT, line_unless=r"DEBUG"),
    r("AND-WEBVIEW-SSL", [r"\.proceed\s*\(\s*\)"], JAVA_KT, requires=r"onReceivedSslError"),
    r("AND-TLS-TRUST-ALL", [r"checkServerTrusted\s*\([^)]*\)[^{;]*\{\s*(//[^\n]*\s*|/\*.*?\*/\s*)*\}",
                            r"(?i)trustAll(Certs|Certificates|Manager)\b"], JAVA_KT, multiline=True),
    r("AND-TLS-HOSTNAME", [r"ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier|NoopHostnameVerifier",
                           r"boolean\s+verify\s*\([^)]*\)\s*\{\s*return\s+true\s*;\s*\}",
                           r"fun\s+verify\s*\([^)]*\)\s*(:\s*Boolean)?\s*(=\s*true|\{\s*return\s+true\s*\})",
                           r"hostnameVerifier\s*(=\s*HostnameVerifier\s*)?\{\s*_\s*,\s*_\s*->\s*true\s*\}"], JAVA_KT, multiline=True),
    r("AND-TLS-INSECURE-FACTORY", [r"SSLCertificateSocketFactory\.getInsecure"], JAVA_KT),
    r("AND-HTTP-URL", [r"\"http://" + NOT_LOCAL_URL + r"[^\"\s]{4,}\""], JAVA_KT + (".xml", ".gradle", ".kts", ".properties")),
    r("AND-CRYPTO-ECB", [r"Cipher\.getInstance\s*\(\s*\"(AES|AES/ECB/[^\"]*)\""], JAVA_KT),
    r("AND-CRYPTO-WEAK-CIPHER", [r"Cipher\.getInstance\s*\(\s*\"(DES|DESede|TripleDES|RC4|ARCFOUR|Blowfish|RC2)\b"], JAVA_KT),
    r("AND-CRYPTO-RSA-NOPAD", [r"Cipher\.getInstance\s*\(\s*\"RSA(/(ECB|NONE)/(PKCS1Padding|NoPadding))?\""], JAVA_KT),
    r("AND-CRYPTO-CBC", [r"\"AES/CBC/[^\"]*\""], JAVA_KT, unless=r"Mac\.getInstance"),
    r("AND-CRYPTO-WEAK-HASH", [r"MessageDigest\.getInstance\s*\(\s*\"(MD5|MD4|MD2|SHA-?1|SHA)\"", r"DigestUtils\.(md5|sha1)\w*\("], JAVA_KT),
    r("AND-CRYPTO-HARDCODED-KEY", [r"SecretKeySpec\s*\(\s*\"[^\"]+\"\s*\.\s*(getBytes|toByteArray)",
                                   r"IvParameterSpec\s*\(\s*(new\s+byte\s*\[\s*\]\s*\{|byteArrayOf\(|\"[^\"]+\"\s*\.)",
                                   r"(?i)\b(static\s+final\s+String|final\s+String|String|val|var|const\s+val)\s+(" + CRYPTO_NAME + r")\s*(:\s*String)?\s*=\s*\"[^\"]{8,}\""],
      JAVA_KT),
    r("AND-CRYPTO-RANDOM", [r"new\s+Random\s*\(", r"java\.util\.Random\b"], JAVA_KT, requires=r"(?i)(token|key|password|nonce|salt|otp|secret|session)"),
    r("AND-CRYPTO-SEED", [r"\.setSeed\s*\(", r"SecureRandom\s*\(\s*[^)\s]"], JAVA_KT),
    r("AND-PREFS-SECRETS", [r"\.put(String|StringSet)\s*\(\s*\"[^\"]*" + SECRET + r"[^\"]*\""], JAVA_KT, unless=r"EncryptedSharedPreferences"),
    r("AND-WORLD-READABLE", [r"MODE_WORLD_(READABLE|WRITEABLE)"], JAVA_KT),
    r("AND-EXTERNAL-STORAGE", [r"getExternalStorageDirectory|getExternalStoragePublicDirectory|getExternalFilesDir|getExternalCacheDir"], JAVA_KT),
    r("AND-SQLITE-PLAIN", [r"extends\s+SQLiteOpenHelper|:\s*SQLiteOpenHelper\(|openOrCreateDatabase\s*\(|Room\.databaseBuilder"], JAVA_KT,
      unless=r"SupportFactory|net\.sqlcipher|SQLCipher|SupportOpenHelperFactory"),
    r("AND-SQLI", [r"(rawQuery|execSQL)\s*\(\s*\"[^\"]*\"\s*\+", r"(rawQuery|execSQL)\s*\(\s*\"[^\"]*\$\{?\w",
                   r"(rawQuery|execSQL)\s*\(\s*String\.format", r"appendWhere\s*\([^)]*\+",
                   r"(?i)\"\s*(SELECT|DELETE|UPDATE|INSERT)\b[^\"]*(=|LIKE)\s*'?\"\s*\+"], JAVA_KT,
      line_unless=r"\"\s*\+\s*[A-Z][A-Z0-9_]*\s*\)?\s*;?\s*$"),
    r("AND-LOGGING", [r"\bLog\.(v|d|i|w|e|wtf)\s*\([^\n]*" + SECRET], JAVA_KT, severity="medium"),
    r("AND-LOGGING", [r"\bLog\.(v|d|i|w|e|wtf)\s*\(", r"System\.out\.print", r"\.printStackTrace\s*\(\s*\)"], JAVA_KT,
      line_unless=SECRET),
    r("AND-CLIPBOARD", [r"setPrimaryClip\s*\(|ClipData\.newPlainText"], JAVA_KT),
    r("AND-EXEC", [r"Runtime\.getRuntime\(\)\.exec\s*\(", r"\bProcessBuilder\s*\("], JAVA_KT),
    r("AND-DYNAMIC-CODE", [r"\b(DexClassLoader|InMemoryDexClassLoader)\s*\("], JAVA_KT),
    r("AND-IMPLICIT-BROADCAST", [r"\bsendBroadcast\s*\(\s*\w+\s*\)"], JAVA_KT),
    r("AND-INTENT-REDIRECT", [r"startActivit(y|ies)(ForResult)?\s*\([^\n]*getParcelableExtra",
                              r"getParcelableExtra\s*(<Intent>)?\s*\([^)]*\)\s*(as\s+Intent|,\s*Intent::class)"], JAVA_KT),
    r("AND-ZIP-SLIP", [r"new\s+File\s*\([^)]*\.getName\(\)\s*\)", r"File\s*\([^)]*(entry|zipEntry|ze)\.name\s*\)"], JAVA_KT,
      requires=r"Zip(Input|)?(Stream|File|Entry)", unless=r"getCanonicalPath|canonicalPath|normalize\(\)|toRealPath"),
    r("AND-BIOMETRIC-NO-CRYPTO", [r"\.authenticate\s*\(\s*\w*[pP]romptInfo\w*\s*\)"], JAVA_KT),
    r("AND-PENDING-INTENT", [r"PendingIntent\.FLAG_MUTABLE"], JAVA_KT, severity="low"),
    r("AND-PENDING-INTENT", [r"PendingIntent\.get(Activity|Service|Broadcast)\s*\([^;\n]*,\s*0\s*\)"], JAVA_KT),
]

GRADLE = (".gradle", ".kts")
ANDROID_BUILD = [
    r("AND-GRADLE-SECRETS", [r"(storePassword|keyPassword)\s*(=\s*)?[\"'][^\"'$]{3,}[\"']",
                             r"buildConfigField\s*\(?\s*[\"']String[\"']\s*,\s*[\"']\w*(KEY|SECRET|TOKEN|PASSWORD)\w*[\"']\s*,\s*[\"']\\?\"[^\"']{6,}"],
      GRADLE),
]

IOS = [
    r("IOS-USERDEFAULTS-SECRETS", [r"UserDefaults\.standard\.set\([^\n]*" + SECRET,
                                   r"NSUserDefaults[^\n]*setObject:[^\n]*" + SECRET,
                                   r"@AppStorage\(\s*\"[^\"]*" + SECRET,
                                   r"UserDefaults\.standard\.set\([^\n]*forKey:\s*\"[^\"]*" + SECRET], SWIFT_OBJC),
    r("IOS-KEYCHAIN-WEAK", [r"kSecAttrAccessibleAlways(ThisDeviceOnly)?\b", r"kSecAttrAccessibleAfterFirstUnlock\b(?!ThisDeviceOnly)"], SWIFT_OBJC),
    r("IOS-FILE-PROTECTION-NONE", [r"NSFileProtectionNone", r"FileProtectionType\.none", r"\.noFileProtection"], SWIFT_OBJC),
    r("IOS-LOGGING", [r"\b(NSLog|print|debugPrint|os_log|Logger\(\)\.\w+)\s*\([^\n]*" + SECRET], SWIFT_OBJC, severity="medium"),
    r("IOS-PASTEBOARD", [r"UIPasteboard\.general\.(string|setValue|items|setString)", r"\[UIPasteboard generalPasteboard\]"], SWIFT_OBJC),
    r("IOS-DB-PLAIN", [r"Realm\.Configuration\((?![^\n]*encryptionKey)", r"\bsqlite3_open(_v2)?\s*\(", r"NSPersistentContainer\("],
      SWIFT_OBJC, unless=r"sqlite3_key|encryptionKey|SQLCipher"),
    r("IOS-WEAK-HASH", [r"\bCC_MD5\b", r"\bCC_SHA1\b", r"Insecure\.MD5", r"Insecure\.SHA1"], SWIFT_OBJC),
    r("IOS-WEAK-CIPHER", [r"kCCOptionECBMode", r"kCCAlgorithm(DES|3DES|RC4|RC2)\b"], SWIFT_OBJC),
    r("IOS-HARDCODED-KEY", [r"(?i)\b(let|var|static\s+let|NSString\s*\*)\s*(" + CRYPTO_NAME + r")\s*(:\s*String)?\s*=\s*@?\"[^\"]{8,}\"",
                            r"(?i)SymmetricKey\(data:\s*\"[^\"]+\"\.data"], SWIFT_OBJC),
    r("IOS-WEAK-RANDOM", [r"\b(rand|random|srand)\s*\(\s*\)"], SWIFT_OBJC),
    r("IOS-TLS-BYPASS", [r"completionHandler\(\s*\.useCredential\s*,\s*URLCredential\(\s*trust:",
                         r"URLCredential\(trust:\s*challenge\.protectionSpace\.serverTrust!?\)",
                         r"setAllowsAnyHTTPSCertificate", r"allowInvalidCertificates\s*=\s*(true|YES)",
                         r"validatesDomainName\s*=\s*(false|NO)", r"DisabledTrustEvaluator\(\)|DisabledEvaluator\(\)",
                         r"kCFStreamSSLValidatesCertificateChain\s*:\s*(false|kCFBooleanFalse|@NO)"], SWIFT_OBJC,
      unless=r"SecTrustEvaluateWithError|SecTrustEvaluate\("),
    r("IOS-HTTP-URL", [r"@?\"http://" + NOT_LOCAL_URL + r"[^\"\s]{4,}\""], SWIFT_OBJC),
    r("IOS-UIWEBVIEW", [r"\bUIWebView\b"], SWIFT_OBJC),
    r("IOS-WKWEBVIEW-BRIDGE", [r"userContentController\.add\(", r"addScriptMessageHandler", r"allowFileAccessFromFileURLs",
                               r"allowUniversalAccessFromFileURLs"], SWIFT_OBJC),
    r("IOS-URL-HANDLER", [r"func\s+application\(\s*_\s+\w+:\s*UIApplication\s*,\s*open\s+url:", r"func\s+scene\([^\n]*openURLContexts",
                          r"\.onOpenURL\s*\{", r"application:\s*\(UIApplication\s*\*\)\w+\s+openURL:"], SWIFT_OBJC),
    r("IOS-BIOMETRIC-EVENT", [r"evaluatePolicy\(\s*\.deviceOwnerAuthentication(WithBiometrics)?", r"evaluatePolicy:LAPolicyDeviceOwner"],
      SWIFT_OBJC, unless=r"SecAccessControlCreateWithFlags"),
    r("IOS-DEBUG-FLAGS", [r"(?i)\b(isDebug|debugMode|enableDebug|skipAuth|bypassSSL|disableSSL)\s*=\s*(true|YES)"], SWIFT_OBJC),
    r("IOS-SQLI", [r"(?i)\"\s*(SELECT|INSERT|UPDATE|DELETE)\b[^\"]*\\\([^\"]*\"",
                   r"(?i)stringWithFormat:\s*@\"\s*(SELECT|INSERT|UPDATE|DELETE)\b[^\"]*%@"], SWIFT_OBJC),
]

CROSS = [
    r("XP-TLS-BYPASS", [r"badCertificateCallback\s*=\s*\([^)]*\)\s*(=>\s*true|\{\s*return\s+true)",
                        r"rejectUnauthorized\s*:\s*false", r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0",
                        r"trustAllCertificates|allowInvalidCertificates\s*:\s*true"], XP),
    r("XP-INSECURE-STORAGE", [r"AsyncStorage\.setItem\s*\(\s*['\"`][^'\"`]*" + SECRET,
                              r"(prefs|preferences|sharedPreferences)\w*\.set(String|StringList)\s*\(\s*['\"][^'\"]*" + SECRET,
                              r"localStorage\.setItem\s*\(\s*['\"`][^'\"`]*" + SECRET,
                              r"MMKV[^\n]*\.set\w*\(\s*['\"][^'\"]*" + SECRET], XP),
    r("XP-WEBVIEW", [r"originWhitelist\s*=\s*\{\s*\[\s*['\"]\*['\"]\s*\]\s*\}", r"allowUniversalAccessFromFileURLs\s*=\s*\{\s*true",
                     r"allowFileAccessFromFileURLs\s*=\s*\{\s*true", r"mixedContentMode\s*=\s*['\"]always['\"]",
                     r"javascriptMode\s*:\s*JavascriptMode\.unrestricted"], XP),
    r("XP-HTTP-URL", [r"['\"`]http://" + NOT_LOCAL_URL + r"[^'\"`\s]{4,}['\"`]"], XP),
    r("XP-LOGGING", [r"\b(console\.(log|debug|info|warn)|debugPrint|print|log)\s*\([^\n]*" + SECRET], XP),
    r("XP-EVAL", [r"\beval\s*\(", r"new\s+Function\s*\("], (".js", ".jsx", ".ts", ".tsx")),
]

HARDCODED_CMP = [
    r("SEC-HARDCODED", [r"(getText\(\)\.toString\(\)|\.text(\.toString\(\))?)\s*(\.equals|==|\.contentEquals)\s*\(?\s*\"[^\"]{4,}\"",
                        r"\.equals\(\s*\"[^\"]{4,}\"\s*\)[^\n]*(?i:pass|pin|key|secret|code|user)",
                        r"(?i)(password|passcode|pin|secret)\w*\s*==\s*\"[^\"]{4,}\""],
      JAVA_KT + SWIFT_OBJC + XP, severity="high"),
]

ALL = HARDCODED_CMP + ANDROID + ANDROID_BUILD + IOS + CROSS
