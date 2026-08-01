---
id: insecure-cookie-example
title: Insecure Cookie (missing Secure flag)
category: examples
---

# Insecure Cookie (missing Secure flag)

**CWE-614** — Sensitive Cookie in HTTPS Session Without 'Secure' Attribute.

Flagged by this repo's `benchmarkjava.insecure-cookie.set-secure-false` rule
([doc](../rules/insecure-cookie.md)). A session cookie created without the
`Secure` attribute (or with it explicitly disabled) is sent by the browser
over plain HTTP as well as HTTPS.

## Vulnerable

```java
protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
    Cookie session = new Cookie("SESSIONID", createSession(req));
    session.setSecure(false);
    session.setPath("/");
    resp.addCookie(session);
}
```

A user on public Wi-Fi who ever hits an `http://` link to the same host
leaks `SESSIONID` in cleartext to anyone on the network path, who can then
replay it to hijack the session.

## Fixed

```java
protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
    Cookie session = new Cookie("SESSIONID", createSession(req));
    session.setSecure(true);
    session.setHttpOnly(true);
    session.setPath("/");
    resp.addCookie(session);
}
```

`setSecure(true)` tells the browser to only ever send the cookie over
HTTPS; `setHttpOnly(true)` additionally blocks JavaScript access to it.
