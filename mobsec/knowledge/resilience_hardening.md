# App Hardening and Anti-Reverse-Engineering (MASVS-RESILIENCE)

## How to think about hardening
Tags: MASVS-RESILIENCE-1, MASVS-RESILIENCE-2, MASVS-RESILIENCE-3, MASVS-RESILIENCE-4, defence in depth, RASP, threat model
Obfuscation, root/jailbreak detection, anti-debugging, anti-hooking and anti-tampering do not fix vulnerabilities; they raise the time and skill needed to reverse engineer, clone, cheat or attack an app. Every client-side check can eventually be bypassed, so: (1) never rely on them to protect secrets or authorization, which must live on the server; (2) layer several independent checks, implemented in different places (Java/Kotlin, native code, server); (3) report detections to your backend and decide there (block, step-up auth, flag the account) rather than only showing a dialog; (4) prefer platform attestation (Play Integrity, App Attest) that the server verifies. Apps handling money, health data, DRM content or competitive games should implement the MASVS-R controls; other apps should at least ship obfuscated, stripped, non-debuggable release builds.

## Android code obfuscation with R8
Tags: MASVS-RESILIENCE-3, M7, CWE-693, R8, ProGuard, minifyEnabled, isMinifyEnabled, repackageclasses, renamesourcefileattribute, mapping.txt
Without R8, jadx output reads like source code. Enable shrinking, obfuscation and resource shrinking for release builds, flatten packages, and hide source file names (they reveal class names even after renaming). Upload mapping.txt to Play Console / Crashlytics so crash reports stay readable.
```kotlin
// app/build.gradle.kts
android {
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            isDebuggable = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
}
```
```
# proguard-rules.pro
-repackageclasses ''
-allowaccessmodification
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable
# strip debug/verbose logs from release
-assumenosideeffects class android.util.Log { public static int v(...); public static int d(...); public static int i(...); }
```
R8 does not encrypt strings, classes used through reflection or JNI must be kept, and names in AndroidManifest.xml stay readable. Commercial protectors (DexGuard, Promon, Appdome, Talsec, Approov and others) add string, class and asset encryption plus runtime checks.

## Plaintext strings and string encryption
Tags: MASVS-RESILIENCE-3, CWE-312, string encryption, StringFog, DexGuard, iXGuard, secrets in binary
Strings in DEX, Mach-O __cstring, resources and JavaScript bundles are visible with `strings`, jadx or class-dump. String encryption only delays an attacker, because the decryption key ships with the app. Fix the root cause first: remove secrets and server URLs that should not be public, move logic server-side, then for high-risk apps add string encryption with a protector or a build plugin (for example StringFog on Android).

## Android root detection
Tags: MASVS-RESILIENCE-1, root detection, Magisk, su, RootBeer, test-keys
Typical indicators: su binaries (/system/xbin/su, /sbin/su), Magisk/SuperSU packages, test-keys builds, writable /system, ro.debuggable=1, dangerous props. Libraries such as RootBeer bundle these checks; Magisk DenyList and Shamiko hide many of them, so combine local checks with Play Integrity (deviceIntegrity verdict) verified on your server.

## Android anti-debugging
Tags: MASVS-RESILIENCE-4, CWE-693, Debug.isDebuggerConnected, TracerPid, JDWP, adb_enabled, ptrace
Release builds should not be debuggable (no android:debuggable), but on rooted devices attackers can force JDWP or attach native debuggers with ptrace. Check several signals and report them:
```kotlin
fun debuggerSignals(ctx: Context): List<String> = buildList {
    if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) add("jdwp")
    if ((ctx.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) add("debuggable")
    val tracer = File("/proc/self/status").readLines().firstOrNull { it.startsWith("TracerPid:") }
        ?.substringAfter(":")?.trim()?.toIntOrNull() ?: 0
    if (tracer != 0) add("ptrace")
    if (Settings.Global.getInt(ctx.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1) add("adb") // informational
}
```
Run the checks at startup and before sensitive operations, and repeat them periodically; native (C/C++) variants are harder to patch out.

## Detecting Frida, Xposed and other hooking frameworks
Tags: MASVS-RESILIENCE-4, CWE-693, Frida, frida-server, frida-gadget, 27042, Xposed, LSPosed, Substrate, /proc/self/maps, dyld
Instrumentation frameworks let attackers change any method's behaviour at runtime (bypassing root checks, pinning and biometric callbacks). Common signals on Android: libraries named frida/gadget/xposed/lsposed in /proc/self/maps, the default frida-server port 27042 on localhost, threads named gum-js-loop or gmain in /proc/self/task/*/comm, Xposed bridge classes loadable via Class.forName("de.robv.android.xposed.XposedBridge"), and unexpected native hooks (modified function prologues). On iOS: injected dylibs found with _dyld_image_count / _dyld_get_image_name (FridaGadget, frida-agent, cynject, libcycript, MobileSubstrate, SubstrateLoader, substitute), the frida port, and symbols resolvable via dlsym that should not exist. Implement checks in native code where possible, randomise when they run, and send results to the server. RASP SDKs (for example the open-source freeRASP by Talsec, or commercial products) package these checks.
```kotlin
fun fridaLoaded(): Boolean = runCatching {
    File("/proc/self/maps").useLines { lines -> lines.any { it.contains("frida", true) || it.contains("gadget", true) } }
}.getOrDefault(false)
```

## Emulator detection
Tags: MASVS-RESILIENCE-1, emulator detection, goldfish, ranchu, Build.FINGERPRINT, qemu, simulator
Attackers use emulators for automated abuse and dynamic analysis. Indicators: Build.FINGERPRINT starting with "generic" or containing "sdk_gphone", Build.HARDWARE "goldfish"/"ranchu", ro.kernel.qemu=1, emulator-specific files (/dev/qemu_pipe), and vendors such as Genymotion, BlueStacks, Nox, LDPlayer. Use as one signal among many; Play Integrity's device verdict is stronger. On iOS check `#if targetEnvironment(simulator)` for debug-only paths and treat simulator usage in production as tampering.

## Android anti-tampering: signature and installer checks
Tags: MASVS-RESILIENCE-2, CWE-354, repackaging, signature verification, GET_SIGNING_CERTIFICATES, getInstallSourceInfo, Play Integrity appIntegrity
Repackaged apps (modified and re-signed with another key) are used for cheating, removing ads or licence checks, and distributing malware under your brand. Compare the signing certificate at runtime with your expected SHA-256, and check the installer:
```kotlin
fun signatureOk(ctx: Context, expectedSha256: String): Boolean {
    val pm = ctx.packageManager
    val sigs = if (Build.VERSION.SDK_INT >= 28)
        pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo?.apkContentsSigners
    else @Suppress("DEPRECATION") pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNATURES).signatures
    val digest = MessageDigest.getInstance("SHA-256")
    return sigs?.any { Base64.encodeToString(digest.digest(it.toByteArray()), Base64.NO_WRAP) == expectedSha256 } == true
}
fun installedFromPlay(ctx: Context): Boolean {
    val installer = if (Build.VERSION.SDK_INT >= 30) ctx.packageManager.getInstallSourceInfo(ctx.packageName).installingPackageName
                    else @Suppress("DEPRECATION") ctx.packageManager.getInstallerPackageName(ctx.packageName)
    return installer == "com.android.vending"
}
```
Local checks can be patched; Play Integrity's appIntegrity verdict (PLAY_RECOGNIZED, certificate digest) verified on your server is the robust control. Store the expected hash in several places or obfuscate it.

## Play Integrity attestation
Tags: MASVS-RESILIENCE-2, Play Integrity API, IntegrityManager, requestIntegrityToken, StandardIntegrityManager, SafetyNet deprecated
SafetyNet Attestation is shut down; use the Play Integrity API. Request a token with a server-generated nonce (classic requests) or use standard requests for frequent checks, send the token to your backend, decrypt and verify it with Google's server API, and check appIntegrity, deviceIntegrity (MEETS_DEVICE_INTEGRITY / MEETS_STRONG_INTEGRITY) and accountDetails before allowing sensitive actions. Never trust a verdict decided on the device.

## Tapjacking and overlay attacks
Tags: MASVS-PLATFORM-3, CWE-1021, tapjacking, overlay, filterTouchesWhenObscured, setHideOverlayWindows, HIDE_OVERLAY_WINDOWS
A malicious app with SYSTEM_ALERT_WINDOW can draw over your app and trick users into tapping buttons (granting permissions, confirming payments) or read what they type in fake overlays. Protect sensitive screens:
```kotlin
// Android 12+: hide non-system overlays while this window is shown (needs <uses-permission android:name="android.permission.HIDE_OVERLAY_WINDOWS"/>)
if (Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)
confirmButton.filterTouchesWhenObscured = true   // or android:filterTouchesWhenObscured="true" in XML
```

## Native code hardening and stripping
Tags: MASVS-RESILIENCE-3, CWE-215, strip, symbols, -fvisibility=hidden, JNI RegisterNatives, obfuscator-llvm
Unstripped .so files keep function names that point straight at sensitive logic, and exported Java_com_example_... JNI symbols reveal the bridge. Build release native code with -fvisibility=hidden, -O2, strip symbols (the Android Gradle Plugin strips by default unless keepDebugSymbols is set), and register JNI methods with RegisterNatives in JNI_OnLoad instead of exporting them. LLVM-based obfuscators add control-flow flattening and string encryption for high-value code.

## iOS obfuscation and symbol stripping
Tags: MASVS-RESILIENCE-3, iOS obfuscation, Swift, Objective-C, class-dump, STRIP_INSTALLED_PRODUCT, STRIP_STYLE, iXGuard, SwiftShield
Objective-C class and selector names are always present in the binary for the runtime, and Swift type metadata keeps type names, so class-dump and Hopper show the app's structure. In the Release configuration set STRIP_INSTALLED_PRODUCT = YES, STRIP_STYLE = all (non-global for frameworks), DEPLOYMENT_POSTPROCESSING = YES, DEBUG_INFORMATION_FORMAT = dwarf-with-dsym (ship the dSYM to your crash reporter, not in the app), and SWIFT_REFLECTION_METADATA_LEVEL = none if you do not use Mirror. For high-risk apps use an obfuscator (commercial iXGuard, or open-source tools such as SwiftShield / obfuscator-llvm forks) and keep sensitive logic server-side.

## iOS jailbreak detection
Tags: MASVS-RESILIENCE-1, jailbreak detection, Cydia, Sileo, /var/jb, rootless, sandbox escape, IOSSecuritySuite
Check several independent signals: jailbreak app and file paths (/Applications/Cydia.app, /var/jb for rootless jailbreaks, /usr/sbin/sshd, /etc/apt), the ability to write outside the sandbox, suspicious dylibs loaded (dyld image list), URL schemes like cydia:// and sileo:// (requires LSApplicationQueriesSchemes), and fork() succeeding. Open-source IOSSecuritySuite bundles many checks. Combine with App Attest on the server, since tools like Shadow or Liberty Lite hide jailbreaks from apps.

## iOS anti-debugging
Tags: MASVS-RESILIENCE-4, ptrace, PT_DENY_ATTACH, sysctl, P_TRACED, getppid, debugger detection
Release builds must have get-task-allow = false (App Store builds do), but jailbroken devices allow debugging anyway. Detect an attached debugger with sysctl and optionally deny attaching with ptrace:
```swift
func isDebuggerAttached() -> Bool {
    var info = kinfo_proc(); var size = MemoryLayout<kinfo_proc>.stride
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
    sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
    return (info.kp_proc.p_flag & P_TRACED) != 0
}
// ptrace(PT_DENY_ATTACH) is not exposed to Swift; resolve it at runtime in release builds only:
typealias PtraceFn = @convention(c) (CInt, pid_t, CInt, CInt) -> CInt
if let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "ptrace") {
    _ = unsafeBitCast(sym, to: PtraceFn.self)(31 /* PT_DENY_ATTACH */, 0, 0, 0)
}
```

## iOS anti-tampering and re-signing detection
Tags: MASVS-RESILIENCE-2, CWE-354, re-signing, embedded.mobileprovision, team identifier, App Attest, DCAppAttestService
Cracked or modified IPAs are re-signed with a different team. Detect it by checking that the app's team identifier (from the keychain access group or Bundle.main entitlements) matches yours, that embedded.mobileprovision is absent in App Store builds, and that no unexpected dylibs are loaded. The robust control is App Attest: generate a key with DCAppAttestService, attest it with Apple, and have your server verify attestations and per-request assertions so modified apps cannot call your API.
```swift
let service = DCAppAttestService.shared
guard service.isSupported else { return }
service.generateKey { keyId, _ in
    guard let keyId else { return }
    let challenge = serverChallengeHash          // SHA-256 of a one-time server nonce
    service.attestKey(keyId, clientDataHash: challenge) { attestation, _ in
        // send keyId + attestation to your server for verification with Apple's root CA
    }
}
```

## iOS screen capture and app-switcher protection
Tags: MASVS-PLATFORM-3, CWE-200, UIScreen.isCaptured, screenshot, app switcher snapshot, sceneWillResignActive
iOS cannot block screenshots, but apps can react: hide sensitive views while UIScreen.main.isCaptured is true (screen recording, AirPlay mirroring), listen for UIApplication.userDidTakeScreenshotNotification, and cover the window in sceneWillResignActive so the app-switcher snapshot shows no data. A common technique is placing sensitive content inside a UITextField with isSecureTextEntry = true, whose layer is excluded from captures.
```swift
NotificationCenter.default.addObserver(forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main) { _ in
    sensitiveView.isHidden = UIScreen.main.isCaptured
}
```

## Packers and commercial protectors
Tags: MASVS-RESILIENCE-3, packer, Jiagu, Bangcle, Legu, DexGuard, protector, RASP
Packers encrypt the real DEX and load it at runtime, so static scanners (including this one) see only the loader stub. Scan the unprotected build to assess the code itself, and confirm the protected build's behaviour dynamically. Some packers are also used by malware, which can trigger store or antivirus flags; prefer reputable protectors and keep their SDKs updated.
