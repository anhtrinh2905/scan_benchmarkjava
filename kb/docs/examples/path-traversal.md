---
id: path-traversal
title: Path Traversal
category: examples
---

# Path Traversal

**CWE-22** — Improper Limitation of a Pathname to a Restricted Directory.

Building a filesystem path from untrusted input without confining it to an
intended base directory lets an attacker escape that directory using `../`
sequences and read (or write) arbitrary files on the host.

## Vulnerable

```java
protected void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws IOException {
    String filename = req.getParameter("file");
    File f = new File("/var/app/uploads/" + filename);
    Files.copy(f.toPath(), resp.getOutputStream());
}
```

Requesting `?file=../../../../etc/passwd` resolves outside
`/var/app/uploads/` and streams back the system password file.

## Fixed

```java
protected void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws IOException {
    String filename = req.getParameter("file");
    Path base = Paths.get("/var/app/uploads/").toRealPath();
    Path resolved = base.resolve(filename).normalize();
    if (!resolved.startsWith(base)) {
        resp.sendError(HttpServletResponse.SC_FORBIDDEN);
        return;
    }
    Files.copy(resolved, resp.getOutputStream());
}
```

Resolving against the canonical base path and rejecting anything that
normalizes outside of it closes off `../` traversal regardless of encoding.
