# Android Data Storage and Cryptography (MASVS-STORAGE, MASVS-CRYPTO, MASVS-AUTH)

## SharedPreferences with credentials or tokens
Tags: MASVS-STORAGE-1, M9, CWE-312, SharedPreferences, putString, EncryptedSharedPreferences, Keystore
SharedPreferences are stored as plain XML in /data/data/<package>/shared_prefs/. They are readable on rooted devices, through `run-as` on debuggable builds, and from backups when allowBackup is on. Storing passwords, access or refresh tokens, PINs or personal data there exposes them. Base64 or a home-made XOR is not encryption.
Fix: avoid storing passwords at all; store tokens encrypted with a key in the Android Keystore. Jetpack Security EncryptedSharedPreferences is deprecated but still works; current guidance is to use Tink or a Keystore-backed AES-GCM key directly:
```kotlin
val spec = KeyGenParameterSpec.Builder("token_key", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .build()
val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec) }
val key = kg.generateKey()
val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
val ct = cipher.doFinal(token.toByteArray()); val iv = cipher.iv   // store iv + ct
```

## World-readable files
Tags: MASVS-STORAGE-2, CWE-276, MODE_WORLD_READABLE, MODE_WORLD_WRITEABLE
MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE make files and preferences accessible to every app. They were deprecated in API 17 and throw SecurityException from API 24, but older devices still honour them. Use MODE_PRIVATE and share data through a permission-protected ContentProvider or FileProvider.

## External storage
Tags: MASVS-STORAGE-2, M9, CWE-922, getExternalStorageDirectory, getExternalFilesDir, WRITE_EXTERNAL_STORAGE, scoped storage
Files on shared external storage were readable by any app holding READ_EXTERNAL_STORAGE (before scoped storage) and remain readable via USB and by file managers. getExternalFilesDir() is app-specific but still not protected on older versions. Keep sensitive files in internal storage (getFilesDir, getNoBackupFilesDir) or encrypt them, and drop WRITE_EXTERNAL_STORAGE where possible.

## SQLite databases
Tags: MASVS-STORAGE-1, CWE-312, SQLiteOpenHelper, Room, SQLCipher
App databases are unencrypted files under databases/. They are fine for non-sensitive data. For sensitive data use SQLCipher (net.zetetic:sqlcipher-android with Room's SupportOpenHelperFactory) with a passphrase protected by the Keystore, or avoid persisting the data.

## SQL injection
Tags: MASVS-CODE-4, M4, CWE-89, rawQuery, execSQL, selectionArgs, appendWhere, Room @Query
Concatenating user input, intent extras, deep-link parameters or provider selection strings into SQL lets attackers read other rows or tables (for example bypassing a login query or dumping a provider). Use placeholders:
```kotlin
db.rawQuery("SELECT * FROM users WHERE name = ? AND pass = ?", arrayOf(name, passHash))
db.query("notes", null, "_id = ?", arrayOf(id), null, null, null)
// Room
@Query("SELECT * FROM user WHERE name = :name") fun find(name: String): User?
```
In content providers call SQLiteQueryBuilder.setStrict(true) and setProjectionMap, and use appendWhereEscapeString for values.

## Logging sensitive data
Tags: MASVS-STORAGE-2, M9, CWE-532, Log.d, Log.e, logcat, printStackTrace, R8 assumenosideeffects
Logcat is readable through adb, bug reports and, on old Android versions, by other apps with READ_LOGS. Log lines with credentials, tokens, card data or server responses leak them. Remove such logs and strip all verbose/debug logging from release builds:
```
-assumenosideeffects class android.util.Log { public static int v(...); public static int d(...); public static int i(...); }
```
printStackTrace also writes to logcat and can expose internals.

## Clipboard
Tags: MASVS-STORAGE-2, CWE-200, ClipboardManager, setPrimaryClip, EXTRA_IS_SENSITIVE
Clipboard contents are readable by the foreground app and keyboards, and before Android 10 by any background app. Avoid copying passwords, OTPs or card numbers. On Android 13+ mark sensitive clips: `clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }`. Disable copy on password fields.

## Screenshots and recent-apps thumbnails
Tags: MASVS-PLATFORM-3, CWE-200, FLAG_SECURE
Without FLAG_SECURE, screens with sensitive data appear in screenshots, screen recordings, casting and the recent-apps thumbnail. Add `window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)` on login, payment and account screens.

## Insecure cipher modes and algorithms
Tags: MASVS-CRYPTO-1, M10, CWE-327, Cipher.getInstance, AES, ECB, DES, RC4, GCM
Cipher.getInstance("AES") silently uses AES/ECB/PKCS5Padding on most providers. ECB encrypts equal blocks to equal ciphertext and has no integrity. DES, 3DES, RC4 and Blowfish are obsolete. CBC without a MAC is malleable and exposed to padding-oracle attacks. Use AES-GCM with a fresh random 12-byte IV for every message:
```kotlin
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, key)               // provider generates a random IV
val ct = cipher.doFinal(plain); val iv = cipher.iv  // store iv with ct
// decrypt: cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
```

## RSA padding
Tags: MASVS-CRYPTO-1, CWE-780, RSA/ECB/PKCS1Padding, OAEP
RSA with PKCS#1 v1.5 encryption padding is vulnerable to Bleichenbacher padding-oracle attacks, and NoPadding is textbook RSA. Use "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" (the "ECB" in the name is meaningless for RSA) and keep the private key in the Android Keystore.

## Hardcoded keys and static IVs
Tags: MASVS-CRYPTO-2, M10, CWE-321, CWE-329, SecretKeySpec, IvParameterSpec, hardcoded key, Android Keystore
A key in the code (a String constant passed to SecretKeySpec, a byte array literal, or a value in strings.xml or BuildConfig) can be pulled out of the APK with jadx in minutes, so everything encrypted with it is effectively plaintext. A fixed IV (all zeros or a constant) leaks equal-plaintext information and breaks GCM completely. Generate keys inside the Android Keystore (they never leave secure hardware on most devices), or derive them from user secrets with PBKDF2/Argon2 and a random salt; never reuse an IV with the same key.

## Weak hashes
Tags: MASVS-CRYPTO-1, CWE-328, MessageDigest MD5, SHA-1
MD5 and SHA-1 are broken for collision resistance. Use SHA-256 or better for integrity, HMAC-SHA256 for authentication, and a slow salted KDF (PBKDF2 with 600k+ iterations, scrypt, Argon2) for passwords. MD5 for non-security purposes (cache keys) is acceptable.

## Random numbers
Tags: MASVS-CRYPTO-1, CWE-330, CWE-337, java.util.Random, SecureRandom, setSeed
java.util.Random is predictable from a few outputs; use java.security.SecureRandom for tokens, OTPs, nonces, salts and keys. Do not call setSeed() or construct SecureRandom with a fixed seed: on some providers that replaces the system entropy and makes output deterministic.

## Biometric authentication without CryptoObject
Tags: MASVS-AUTH-2, M3, CWE-287, BiometricPrompt, CryptoObject, setUserAuthenticationRequired
Calling BiometricPrompt.authenticate(promptInfo) and unlocking on onAuthenticationSucceeded is event-bound: on a rooted device Frida can call the success callback directly. Bind authentication to cryptography: create a Keystore key with setUserAuthenticationRequired(true) (and setInvalidatedByBiometricEnrollment(true)), pass a Cipher using it in BiometricPrompt.CryptoObject, and only use the key (for example to decrypt a stored refresh token) inside the success callback.

## Hardcoded credentials and API keys
Tags: MASVS-STORAGE-1, M1, CWE-798, API key, client secret, BuildConfig, strings.xml, gradle.properties
Everything in an APK (code, strings.xml, assets, BuildConfig fields, native libraries) can be extracted. Secrets for paid APIs, cloud accounts or admin back-doors must not be in the app. Move them to a backend that authenticates the user and calls the third-party API, rotate leaked keys immediately, and restrict any key that must be in the app (Google Maps, Firebase) by package name and SHA-1 signing certificate in the provider console. Keep signing passwords out of build.gradle (use environment variables or CI secrets).
