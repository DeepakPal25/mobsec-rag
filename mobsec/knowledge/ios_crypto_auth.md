# iOS Cryptography and Authentication (MASVS-CRYPTO, MASVS-AUTH)

## Weak hash functions
Tags: MASVS-CRYPTO-1, M10, CWE-328, CC_MD5, CC_SHA1, Insecure.MD5
MD5 and SHA-1 have practical collision attacks. Apple's CryptoKit places them under the Insecure namespace and CommonCrypto marks CC_MD5 deprecated. They are acceptable only for non-security checksums. For integrity use SHA256 or SHA512 from CryptoKit; for MACs use HMAC<SHA256>. Passwords must never be stored as a plain hash at all; use a slow KDF such as PBKDF2 (CCKeyDerivationPBKDF with high iterations) or Argon2, ideally on the server.

## Broken ciphers and ECB mode
Tags: MASVS-CRYPTO-1, CWE-327, kCCOptionECBMode, DES, 3DES, RC4, AES-GCM
ECB encrypts identical blocks to identical ciphertext, leaking data patterns, and provides no integrity. DES, 3DES, RC2 and RC4 are obsolete. CBC without a MAC is open to padding-oracle attacks. Use authenticated encryption: CryptoKit AES.GCM.seal / open or ChaChaPoly, with a fresh random nonce per message (CryptoKit generates it if you do not pass one).

## Hardcoded keys and IVs
Tags: MASVS-CRYPTO-2, CWE-321, key management, SymmetricKey, Secure Enclave
A key compiled into the app can be pulled out of the binary in minutes with strings, Hopper or Ghidra, so encryption with it protects nothing. Static IVs or salts also weaken encryption. Generate keys at runtime with SymmetricKey(size: .bits256), store them in the Keychain with a strict accessibility class, or use the Secure Enclave (SecureEnclave.P256) for asymmetric keys that never leave the hardware. Keys that must be shared with a server should be derived through a key-agreement protocol or delivered per session after authentication.

## Random numbers
Tags: MASVS-CRYPTO-1, CWE-338, SecRandomCopyBytes, arc4random
For nonces, tokens, salts and keys use SecRandomCopyBytes or SystemRandomNumberGenerator (which is cryptographically secure on Apple platforms). rand() and srand() are predictable. arc4random is backed by a secure generator on modern Apple OSes but SecRandomCopyBytes states the intent clearly and is the recommended API in reviews.

## LocalAuthentication bypass
Tags: MASVS-AUTH-2, M3, CWE-287, LAContext, evaluatePolicy, biometryCurrentSet, SecAccessControl
Calling LAContext.evaluatePolicy and then unlocking the app when the callback returns success = true is event-bound authentication: on a jailbroken device a hooking tool (Frida, objection `ios ui biometrics_bypass`) can force the callback to return true. The stronger pattern binds the biometric to a Keychain item: create the item with SecAccessControlCreateWithFlags(..., kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, ...). Reading the item makes the OS itself demand the biometric, and the secret (for example a refresh token) is only released when it succeeds. .biometryCurrentSet also invalidates the item when fingerprints or faces are added.

## Credentials in the app
Tags: MASVS-STORAGE-1, M1, CWE-798, API key, client secret, hardcoded credentials
Everything inside the IPA (code, Info.plist, JSON, .xcconfig values compiled in) should be treated as public. API keys, OAuth client secrets, cloud keys (AWS AKIA..., Stripe sk_live_...), and private keys found there must be rotated and removed. Use a backend that holds the secret and issues short-lived, user-scoped tokens. Keys that are designed to be public (Firebase web API keys, Google Maps keys) should still be restricted by bundle ID and API scope in the provider console.

## Session and token handling
Tags: MASVS-AUTH-1, tokens, session, logout
Keep access tokens short-lived, store refresh tokens in the Keychain, revoke them server-side on logout, and enforce authorization on the server, never only in the UI. Any security decision the app makes locally (for example "isPremium" or "isAdmin" flags) can be changed by the user.
