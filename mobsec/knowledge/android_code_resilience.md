# Android Code Quality, Native Code and Resilience (MASVS-CODE, MASVS-RESILIENCE)

## Command execution
Tags: MASVS-CODE-4, CWE-78, Runtime.exec, ProcessBuilder
Runtime.exec and ProcessBuilder run shell commands with the app's permissions. Passing any externally influenced string (intent extras, file names, server data) allows command injection. Most legitimate uses are root detection (`which su`) or diagnostics. Avoid the shell, use Java APIs, and pass arguments as an array, never as a single concatenated string.

## Dynamic code loading
Tags: MASVS-CODE-4, M2, CWE-94, DexClassLoader, InMemoryDexClassLoader, System.load
Loading DEX or native code from external storage, downloads or other apps' directories lets an attacker who can write that file run code inside the app. Load code only from the APK or app-private storage, verify a signature or hash before loading, and prefer Play Feature Delivery for on-demand modules. From Android 14, dynamically loaded files must be read-only.

## Zip Slip
Tags: MASVS-CODE-4, CWE-22, ZipInputStream, ZipEntry.getName, path traversal
Archive entries can contain names like ../../shared_prefs/settings.xml. Writing File(targetDir, entry.name) without validation overwrites arbitrary app files, which can lead to code execution (overwriting dex/odex or native libraries).
```kotlin
val out = File(targetDir, entry.name)
if (!out.canonicalPath.startsWith(targetDir.canonicalPath + File.separator)) throw SecurityException("Zip path traversal")
```

## Native libraries hardening
Tags: MASVS-CODE-4, M7, CWE-119, CWE-121, NX, stack canary, RELRO, FORTIFY_SOURCE, strcpy
Native code compiled without stack protectors (-fstack-protector-strong), with an executable stack, or without full RELRO (-Wl,-z,relro,-z,now) is easier to exploit if a memory-safety bug exists. Modern NDK toolchains enable these by default; missing protections usually mean an old or prebuilt third-party library. Unsafe C functions (strcpy, sprintf, gets) are a common source of overflows; use bounded versions and enable _FORTIFY_SOURCE=2.

## Obfuscation and code shrinking
Tags: MASVS-RESILIENCE-3, M7, CWE-693, R8, ProGuard, minifyEnabled
Without R8 (minifyEnabled true) the APK keeps original class and method names, so jadx output reads almost like the source code, making reverse engineering, finding hardcoded values and patching trivial. Enable minification and resource shrinking for release builds; obfuscation is a speed bump, not protection for secrets.

## Root detection and app integrity
Tags: MASVS-RESILIENCE-1, MASVS-RESILIENCE-2, Play Integrity API, root detection, RootBeer, tampering
Client-side root checks (su binaries, Magisk packages, test-keys) are easy to bypass with Frida or Magisk hide but raise attacker effort. The robust control is server-side attestation: request a Play Integrity token for sensitive actions and verify the verdict (app recognized, device integrity) on your backend before trusting the request. Use for banking, payments, DRM and games with economies.

## Third-party SDKs and supply chain
Tags: MASVS-CODE-3, MASVS-PRIVACY-1, M2, M6, third-party SDK, analytics, advertising
Each SDK runs with the app's permissions and can collect device identifiers, location and usage data. Keep an inventory, update regularly (check GitHub Advisory / OSV for CVEs), remove unused SDKs, configure them for minimal data collection, and declare their data in Google Play's Data safety form.

## Firebase and cloud backends
Tags: MASVS-NETWORK-1, M8, CWE-284, firebaseio.com, Firebase Realtime Database rules, S3 bucket
A Firebase Realtime Database URL in the app is expected, but if its security rules allow public read/write (`".read": true`) the whole database can be dumped with `curl https://<project>.firebaseio.com/.json`. Lock rules to authenticated users (`auth != null` and per-user paths), and similarly make cloud storage buckets private and serve files via signed URLs.
