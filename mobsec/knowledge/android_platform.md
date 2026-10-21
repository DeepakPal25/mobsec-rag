# Android Platform Interaction and Manifest Security (MASVS-PLATFORM, MASVS-CODE)

## Exported components and access control
Tags: MASVS-PLATFORM-1, M8, CWE-926, android:exported, activity, service, receiver, provider, intent-filter
Any activity, service, broadcast receiver or content provider with android:exported="true" can be started or queried by every other app on the device. Before Android 12 (targetSdk 31), a component with an intent-filter was exported implicitly. Attackers use exported components to open screens that should sit behind login (for example a PostLogin or Transfer activity), to trigger services with crafted extras, to send spoofed broadcasts, or to read and write a provider's database.
Fix: set android:exported="false" for everything that is only used inside the app. When another app must call the component, protect it with a custom permission whose android:protectionLevel is "signature", check Binder.getCallingUid() or the calling package where relevant, and treat every extra, URI and bundle as untrusted input.
Test idea: `adb shell am start -n <pkg>/<activity>`; `adb shell am broadcast -a <action> -n <pkg>/<receiver>`; `adb shell content query --uri content://<authority>/...`; or drozer `run app.package.attacksurface`.
Kotlin example:
```xml
<activity android:name=".TransferActivity" android:exported="false" />
<permission android:name="com.example.permission.INTERNAL" android:protectionLevel="signature" />
<service android:name=".SyncService" android:exported="true" android:permission="com.example.permission.INTERNAL" />
```

## Content provider risks
Tags: MASVS-PLATFORM-1, MASVS-CODE-4, CWE-89, CWE-22, ContentProvider, query, selection, openFile, grantUriPermissions, FileProvider
Exported providers are the most dangerous component type because they expose data directly. Typical bugs: building SQL from the projection, selection or sortOrder (SQL injection through `content query --where`), path traversal in openFile() when the URI path is joined to a directory without canonicalization, and FileProvider path configs that share root-path or the whole files directory. grantUriPermissions lets the app hand out temporary access; combined with an intent redirection bug it can leak private files.
Fix: export only when needed with readPermission/writePermission at signature level, use SQLiteQueryBuilder.setStrict(true) and setProjectionMap, pass user values through selectionArgs, canonicalize file paths and verify they stay inside the allowed directory, and restrict FileProvider <paths> to specific subfolders.

## Intent redirection and PendingIntent
Tags: MASVS-PLATFORM-1, CWE-940, CWE-927, getParcelableExtra, startActivity, PendingIntent, FLAG_IMMUTABLE
If an exported component takes an Intent from an extra (getParcelableExtra("next_intent")) and calls startActivity on it, an attacker can make the app launch its own non-exported components with the app's identity, or grant URI permissions to private files. Mutable PendingIntents with implicit base intents can be filled in by the receiving app.
Fix: never launch intents taken from untrusted extras; if unavoidable, check resolveActivity() points to an allowed component and strip FLAG_GRANT_* flags. Create PendingIntents with FLAG_IMMUTABLE and an explicit component.

## Implicit broadcasts
Tags: MASVS-PLATFORM-1, CWE-927, sendBroadcast, LocalBroadcastManager, receiver permission
sendBroadcast(intent) with an implicit intent can be received by any app that registers a matching receiver, leaking data in the extras (for example a changed password sent by SMS intent in InsecureBank). Use explicit intents (intent.setPackage(packageName)), sendBroadcast(intent, permission) with a signature permission, or in-process mechanisms (LiveData, Flow, LocalBroadcastManager for legacy code). For receivers registered at runtime use RECEIVER_NOT_EXPORTED.

## Deep links and App Links
Tags: MASVS-PLATFORM-1, M4, CWE-939, deep link, BROWSABLE, scheme, autoVerify, App Links
Custom schemes (myapp://) can be claimed by any app and invoked by any web page. http/https links without android:autoVerify="true" show a disambiguation dialog and can be hijacked. Parameters from deep links reach WebViews, SQL and navigation code and are a common injection vector.
Fix: use verified Android App Links (autoVerify plus assetlinks.json on your domain), validate host, path and every query parameter, never load arbitrary URLs from a link parameter into a WebView, and require re-authentication before sensitive actions reached by links.

## Task hijacking (StrandHogg)
Tags: MASVS-PLATFORM-3, CWE-1021, taskAffinity, launchMode, singleTask, allowTaskReparenting
On Android versions before 11, a malicious app can set its taskAffinity to the victim package and get its activity placed into the victim's task, showing a phishing screen when the user opens the real app. launchMode="singleTask" and allowTaskReparenting make it easier.
Fix: set android:taskAffinity="" at the application level, avoid singleTask/singleInstance unless needed, and raise minSdk to 30 where possible.

## Debuggable, testOnly and backup flags
Tags: MASVS-RESILIENCE-4, MASVS-STORAGE-2, CWE-489, CWE-530, android:debuggable, allowBackup, fullBackupContent, dataExtractionRules, testOnly
android:debuggable="true" lets anyone with USB access attach a debugger (jdb via JDWP), run code as the app with `run-as`, and read its private files. Release builds from Gradle are never debuggable unless the manifest or buildTypes force it. android:allowBackup defaults to true: `adb backup` (before Android 12) and cloud backup copy app data, including SharedPreferences tokens and databases, off the device.
Fix: remove android:debuggable from the manifest and let build types control it. Set android:allowBackup="false", or keep backup and exclude sensitive files with android:dataExtractionRules (Android 12+) and android:fullBackupContent (older). Never ship testOnly APKs.

## Permissions and protection levels
Tags: MASVS-PLATFORM-1, MASVS-PRIVACY-1, CWE-276, protectionLevel, signature, dangerous permissions
Custom permissions with protectionLevel normal are granted to any app that asks; dangerous ones only need one user tap. A permission meant to guard an internal component must be signature-level. Request only the dangerous permissions a feature needs (camera, location, contacts, SMS, call log) at the moment of use, and declare them in the Play Data safety form.

## Outdated minSdk and targetSdk
Tags: MASVS-CODE-3, CWE-1104, minSdkVersion, targetSdkVersion
A low minSdkVersion lets the app run on OS versions without security patches, where several platform weaknesses are known (for example addJavascriptInterface reflection RCE below API 17, Janus below 7.0, cleartext by default below 9). A low targetSdkVersion opts out of newer protections such as default cleartext blocking (28), scoped storage (29/30), explicit exported flags (31) and safer PendingIntent defaults (31). Google Play requires a recent target.

## APK signing
Tags: MASVS-CODE-2, CWE-347, CWE-296, v1 signature, Janus, CVE-2017-13156, debug certificate
APKs signed only with the JAR (v1) scheme can be modified on Android 5.0-8.0 by prepending a DEX file without breaking the signature (Janus, CVE-2017-13156). Modern Android Gradle Plugin signs with v2/v3 automatically. A release signed with the Android debug key (CN=Android Debug) means anyone with the widely known debug keystore setup can produce an update-compatible APK only if they also have that exact key, but it shows the release process is broken, and Play rejects such builds.
