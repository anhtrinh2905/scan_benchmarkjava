---
id: insecure-cookie
title: Insecure Cookie (insecure-cookie)
category: rules
---

# Rule: `benchmarkjava.insecure-cookie.set-secure-false`

Defined in `rules/benchmarkjava/insecure-cookie.yaml`. Flags the exact
pattern `$C.setSecure(false)` — a cookie object explicitly told not to
require HTTPS.

**What it flags:** a call site that sets a cookie's `Secure` attribute to
`false`, meaning the browser will send that cookie over plain HTTP as well
as HTTPS.

**CWE:** CWE-614 — Sensitive Cookie in HTTPS Session Without 'Secure' Attribute.

**Why it's a finding:** without the `Secure` flag, a cookie (often carrying a
session identifier) is sent over any connection the user's browser makes to
the host, including unencrypted HTTP. A network attacker in a
man-in-the-middle position (public Wi-Fi, compromised router) can read the
cookie in transit and hijack the session.

**Fix:**

```java
// Before — CWE-614
Cookie session = new Cookie("SESSIONID", sessionId);
session.setSecure(false);
response.addCookie(session);

// After
Cookie session = new Cookie("SESSIONID", sessionId);
session.setSecure(true);
session.setHttpOnly(true);
response.addCookie(session);
```
