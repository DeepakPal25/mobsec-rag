# Android Network Security and WebView (MASVS-NETWORK, MASVS-PLATFORM-2)

## Cleartext traffic and Network Security Configuration
Tags: MASVS-NETWORK-1, M5, CWE-319, usesCleartextTraffic, network_security_config, cleartextTrafficPermitted, base-config, domain-config
Since targetSdk 28 Android blocks cleartext HTTP by default. android:usesCleartextTraffic="true" or a <base-config cleartextTrafficPermitted="true"> re-enables it for every host, so traffic can be read or modified on public Wi-Fi. Apps targeting below 28 allow cleartext unless they ship a network security config.
Fix: remove the flag, use HTTPS everywhere, and if a legacy host really needs HTTP, allow it only for that host:
```xml
<network-security-config>
  <base-config cleartextTrafficPermitted="false" />
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="false">legacy.example.com</domain>
  </domain-config>
</network-security-config>
```

## Trusting user-installed CAs
Tags: MASVS-NETWORK-1, CWE-295, trust-anchors, certificates src="user", debug-overrides, overridePins
From Android 7 apps trust only system CAs by default. Adding <certificates src="user"/> to base-config or domain-config makes the app trust any CA the user (or malware, or an MDM, or someone with brief device access) installs, enabling interception. overridePins="true" lets those CAs bypass pinning. Put user CAs only inside <debug-overrides>, which applies to debuggable builds only.

## Custom TrustManager that accepts everything
Tags: MASVS-NETWORK-1, M5, CWE-295, X509TrustManager, checkServerTrusted, trust all, SSLContext
An X509TrustManager whose checkServerTrusted() is empty accepts any certificate, so any man-in-the-middle with a self-signed certificate can read and change all HTTPS traffic. It often comes from a Stack Overflow snippet added to talk to a test server and left in release. Google Play rejects apps with this pattern.
Fix: delete the custom TrustManager and SSLContext setup and use the platform default. For self-signed test servers, add the test CA in <debug-overrides>. For pinning use the network security config <pin-set> or OkHttp CertificatePinner:
```kotlin
val client = OkHttpClient.Builder()
    .certificatePinner(CertificatePinner.Builder()
        .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        .add("api.example.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=") // backup key
        .build())
    .build()
```

## Hostname verification disabled
Tags: MASVS-NETWORK-1, CWE-297, HostnameVerifier, verify return true, ALLOW_ALL_HOSTNAME_VERIFIER, NoopHostnameVerifier
A HostnameVerifier that returns true accepts a valid certificate issued for any domain, so an attacker with a certificate for their own domain can intercept traffic. Use the default verifier (HttpsURLConnection.getDefaultHostnameVerifier / OkHttp default).

## Certificate pinning
Tags: MASVS-NETWORK-2, pin-set, CertificatePinner, TrustKit, pin expiration
Pinning limits accepted certificates to known public keys, defending against compromised or mis-issued CAs and user-installed CAs. Pin the SPKI hash of your intermediate or leaf key, always include a backup pin, set an expiration in <pin-set expiration="..."> so a stale app does not brick, and have a rotation plan. It is recommended for finance, health and other high-risk apps.

## WebView JavaScript bridge (addJavascriptInterface)
Tags: MASVS-PLATFORM-2, M4, CWE-749, addJavascriptInterface, @JavascriptInterface, WebMessageListener
addJavascriptInterface exposes a Java object to every page loaded in the WebView. Below API 17 any public method, including getClass(), was reachable, giving remote code execution through reflection. On newer versions only @JavascriptInterface methods are exposed, but any page (including one injected via HTTP, an open redirect or a deep link parameter) can call them.
Fix: load only HTTPS content you control, check the current URL's origin inside each bridge method, expose the minimum, and prefer WebViewCompat.addWebMessageListener with an allowed-origin set.

## WebView file access
Tags: MASVS-PLATFORM-2, CWE-749, setAllowFileAccessFromFileURLs, setAllowUniversalAccessFromFileURLs, setAllowFileAccess, WebViewAssetLoader
setAllowUniversalAccessFromFileURLs(true) lets a file:// page read any URL including other files and remote origins; setAllowFileAccessFromFileURLs(true) lets it read other local files. Combined with loading attacker-influenced files (downloads, deep links) this leads to theft of app-private files such as shared_prefs XML and databases.
Fix: keep both false (the default since API 16), call setAllowFileAccess(false) (default false from API 30), and serve bundled content through androidx.webkit.WebViewAssetLoader over https://appassets.androidplatform.net.

## JavaScript in WebView and XSS
Tags: MASVS-PLATFORM-2, CWE-79, setJavaScriptEnabled, loadUrl, loadData, evaluateJavascript
JavaScript is off by default. Enabling it is fine for trusted HTTPS content, but if the WebView loads URLs from intents, deep links or user input, or builds HTML with string concatenation, attackers get script execution in the app's WebView, which can reach bridges, cookies and file access. Validate URLs against an allowlist in shouldOverrideUrlLoading and escape data placed in HTML.

## SSL errors in WebView
Tags: MASVS-NETWORK-1, CWE-295, onReceivedSslError, SslErrorHandler.proceed
Overriding WebViewClient.onReceivedSslError and calling handler.proceed() accepts invalid certificates for pages in the WebView. Google Play blocks apps that do this. Remove the override or call handler.cancel().

## WebView remote debugging
Tags: MASVS-RESILIENCE-4, setWebContentsDebuggingEnabled
WebView.setWebContentsDebuggingEnabled(true) lets anyone with USB access inspect and run JavaScript in the app's WebViews through chrome://inspect. Guard it with `if (BuildConfig.DEBUG)`.
