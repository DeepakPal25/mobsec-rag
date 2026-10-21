# Cross-platform Apps: Flutter, React Native, Cordova (MASVS)

## Secure storage in Flutter and React Native
Tags: MASVS-STORAGE-1, M9, CWE-312, AsyncStorage, shared_preferences, flutter_secure_storage, react-native-keychain, MMKV
React Native AsyncStorage and Flutter shared_preferences write plain files (SharedPreferences XML on Android, plist/UserDefaults on iOS). Tokens and credentials there are as exposed as native plaintext storage. Use flutter_secure_storage (Keychain / Keystore backed) or react-native-keychain / expo-secure-store. MMKV encryption needs a key from secure storage, not a hardcoded string.

## Disabled certificate validation in Flutter / JavaScript
Tags: MASVS-NETWORK-1, CWE-295, badCertificateCallback, HttpClient, rejectUnauthorized, NODE_TLS_REJECT_UNAUTHORIZED
Dart `HttpClient()..badCertificateCallback = (cert, host, port) => true` accepts any certificate, enabling man-in-the-middle. The same applies to `rejectUnauthorized: false` in JavaScript HTTP agents. Remove these; for pinning use packages such as http_certificate_pinning or react-native-ssl-pinning, or native network security config / NSPinnedDomains.

## WebView configuration in React Native / Flutter
Tags: MASVS-PLATFORM-2, CWE-749, react-native-webview, originWhitelist, webview_flutter, JavascriptMode, onMessage
`originWhitelist={['*']}` lets the WebView navigate anywhere while keeping the injectedJavaScript and onMessage bridge connected. allowFileAccessFromFileURLs / allowUniversalAccessFromFileURLs expose local files. Restrict origins to your domains, validate event.nativeEvent.url / origin in onMessage handlers, keep file access off, and in Flutter use JavaScriptMode.unrestricted only for trusted content with NavigationDelegate allowlisting.

## JavaScript bundles and hardcoded secrets
Tags: MASVS-STORAGE-1, M1, CWE-798, index.android.bundle, main.jsbundle, .env, react-native-config
The React Native bundle ships as readable JavaScript (or Hermes bytecode, which is easily decompiled). Values from .env files via react-native-config or babel plugins are embedded in plain text. Treat every value in the bundle as public; keep secrets on a backend.

## eval and dynamic code
Tags: MASVS-CODE-4, CWE-95, eval, new Function, CodePush
eval() or new Function() on data from the network, deep links or storage allows code injection. Over-the-air update systems (CodePush, Expo Updates) must use code signing so a compromised server cannot push malicious JavaScript.

## Flutter specifics
Tags: MASVS-RESILIENCE-3, Flutter, libapp.so, Dart AOT, obfuscate, split-debug-info
Dart code is AOT-compiled into libapp.so, which hides it from jadx but tools like Blutter and reFlutter recover classes and strings. Build release with `--obfuscate --split-debug-info=<dir>`. Strings, including API keys, are still visible in the binary.
