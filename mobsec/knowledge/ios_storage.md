# iOS Data Storage (MASVS-STORAGE)

## UserDefaults is plaintext storage
Tags: MASVS-STORAGE-1, M9, CWE-312, UserDefaults, NSUserDefaults, AppStorage
UserDefaults (NSUserDefaults, and SwiftUI @AppStorage on top of it) writes to a property list in the app container at Library/Preferences/<bundle-id>.plist. The file is not encrypted by the app, is included in iTunes/Finder and iCloud backups, and is readable on a jailbroken device or from an unencrypted backup. It is fine for preferences such as theme or onboarding flags. It must not hold passwords, OAuth access or refresh tokens, session IDs, PINs, or personal data.
Fix: store secrets in the Keychain using SecItemAdd with kSecClassGenericPassword, or a small wrapper such as KeychainAccess. Delete legacy values from UserDefaults on upgrade so old copies do not linger.
Test idea: run the app, log in, then inspect Library/Preferences/*.plist in the container (simulator path or objection `ios nsuserdefaults get`).

## Keychain accessibility classes
Tags: MASVS-STORAGE-1, kSecAttrAccessible, keychain, data protection
Every Keychain item has an accessibility attribute that decides when iOS can decrypt it. kSecAttrAccessibleAlways and kSecAttrAccessibleAlwaysThisDeviceOnly are deprecated and allow access even when the device is locked. kSecAttrAccessibleAfterFirstUnlock keeps items readable after the first unlock until reboot and, without the ThisDeviceOnly suffix, migrates to new devices through encrypted backups.
Recommended: kSecAttrAccessibleWhenUnlockedThisDeviceOnly for most secrets; kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly for the most sensitive items (removed if the passcode is disabled). Use AfterFirstUnlockThisDeviceOnly only when background tasks truly need the item.
Note: Keychain items survive app deletion. Clear them on first launch after install if the app should start fresh.

## File Data Protection classes
Tags: MASVS-STORAGE-1, NSFileProtectionComplete, FileProtectionType, completeFileProtection
Files are encrypted with keys tied to a protection class. NSFileProtectionNone / FileProtectionType.none means the file key is available whenever the device is on. The default for app files is CompleteUntilFirstUserAuthentication. For sensitive files, write with Data.write(to:options: .completeFileProtection) or set FileAttributeKey.protectionKey to .complete, so the file is unreadable while the device is locked.
The app-wide default can also be raised with the Data Protection capability (com.apple.developer.default-data-protection = NSFileProtectionComplete).

## Local databases: SQLite, Core Data, Realm
Tags: MASVS-STORAGE-1, sqlite3_open, NSPersistentContainer, Realm, encryption
SQLite, Core Data (backed by SQLite) and Realm store data in clear form inside the container. The OS file protection class applies, but anyone with a backup or jailbreak access can read the database. Avoid persisting sensitive data at all where possible. When it is needed, use SQLCipher for SQLite, or Realm's encryptionKey (64 bytes) with the key generated randomly and stored in the Keychain. Remember the WAL and SHM side files also contain data.

## Sensitive data in logs
Tags: MASVS-STORAGE-2, M9, CWE-532, NSLog, print, os_log
NSLog and print output goes to the unified system log and can be read through Console.app on a connected Mac or by crash/diagnostic tooling. Logging tokens, passwords, request bodies or personal data leaks them. Use os_log / Logger with privacy annotations (for example "\(token, privacy: .private)"), and wrap debug logging in #if DEBUG so release builds compile it out.

## Pasteboard leakage
Tags: MASVS-STORAGE-2, UIPasteboard, clipboard
UIPasteboard.general is shared across apps, and with Universal Clipboard across the user's devices. Copying a password or OTP to it exposes the value to other apps. Disable copy on sensitive text fields, or set items with UIPasteboard.OptionsKey.localOnly and a short expirationDate.

## Backups, snapshots and keyboard cache
Tags: MASVS-STORAGE-2, isExcludedFromBackup, app switcher snapshot, keyboard cache
Files in Documents/ and Library/ (except Caches) are backed up. Use isExcludedFromBackup for sensitive files, while knowing it is only a hint to the system. When the app goes to the background, iOS takes a screenshot for the app switcher; hide sensitive screens in sceneWillResignActive. For secret text fields set isSecureTextEntry or autocorrectionType = .no to keep values out of the keyboard cache.

## File sharing exposure
Tags: MASVS-STORAGE-2, UIFileSharingEnabled, LSSupportsOpeningDocumentsInPlace
With UIFileSharingEnabled the Documents directory appears in the Files app and in Finder. Anything sensitive placed in Documents becomes trivially readable by whoever holds the unlocked device. Keep sensitive files in Library/Application Support with complete protection.
