# iOS Network Communication (MASVS-NETWORK)

## App Transport Security (ATS) basics
Tags: MASVS-NETWORK-1, M5, CWE-319, NSAppTransportSecurity, NSAllowsArbitraryLoads
ATS is enforced by default for URLSession and requires HTTPS with TLS 1.2 or newer, forward-secret cipher suites and valid certificates. NSAllowsArbitraryLoads = YES in Info.plist turns ATS off for every connection, allowing cleartext HTTP and weak TLS. App Review may ask for justification. Removing the global flag and adding scoped exceptions is the fix.

## ATS exception domains
Tags: MASVS-NETWORK-1, NSExceptionDomains, NSExceptionAllowsInsecureHTTPLoads, NSExceptionMinimumTLSVersion, NSIncludesSubdomains
NSExceptionDomains lets the app relax ATS per host. NSExceptionAllowsInsecureHTTPLoads permits plain HTTP to that host; NSExceptionMinimumTLSVersion of TLSv1.0 or TLSv1.1 allows deprecated protocols; NSIncludesSubdomains widens the exception. Every exception should map to a host you do not control and cannot upgrade, documented with a reason. Traffic to your own backend should never need one.

## ATS web content and media exceptions
Tags: MASVS-NETWORK-1, NSAllowsArbitraryLoadsInWebContent, NSAllowsArbitraryLoadsForMedia
NSAllowsArbitraryLoadsInWebContent disables ATS for WKWebView loads only, and NSAllowsArbitraryLoadsForMedia for AVFoundation media. They are narrower than the global flag but still let pages or streams load over HTTP, where they can be modified in transit. Use them only for browser-like features.

## Disabled server trust evaluation
Tags: MASVS-NETWORK-1, CWE-295, URLSessionDelegate, didReceive challenge, serverTrust, useCredential
A common bug is implementing urlSession(_:didReceive:completionHandler:) and always calling completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!)). That accepts any certificate, including an attacker's, making man-in-the-middle trivial on hostile Wi-Fi. Similar mistakes: Alamofire ServerTrustManager with DisabledTrustEvaluator, AFNetworking allowInvalidCertificates = YES, validatesDomainName = NO.
Correct pattern: for NSURLAuthenticationMethodServerTrust, first evaluate the trust with SecTrustEvaluateWithError; if it fails call completionHandler(.cancelAuthenticationChallenge, nil). If you are not adding pinning, call completionHandler(.performDefaultHandling, nil) and let the system validate.
Test idea: route the device through an intercepting proxy without installing its CA. If requests still succeed, validation is broken.

## Certificate and public-key pinning
Tags: MASVS-NETWORK-2, NSPinnedDomains, pinning, TrustKit, SPKI
Pinning restricts which certificates the app accepts for your hosts, which protects against mis-issued certificates and user-installed CAs. Since iOS 14, NSPinnedDomains in Info.plist supports declarative pinning by SPKI-SHA256 hashes (NSPinnedLeafIdentities or NSPinnedCAIdentities). In code, compare SecTrustCopyKey output against stored hashes after SecTrustEvaluateWithError succeeds. Always pin at least one backup key so certificate rotation does not break the app. Pinning is recommended for banking, health and other high-risk apps; it is defense-in-depth rather than a baseline requirement.

## Cleartext HTTP URLs in code
Tags: MASVS-NETWORK-1, http://, cleartext
Hardcoded http:// endpoints either fail under ATS or indicate ATS has been relaxed. Data sent over HTTP can be read and modified by anyone on the network path. Switch to https:// and remove the matching exceptions.
