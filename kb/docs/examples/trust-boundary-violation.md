---
id: trust-boundary-violation
title: Trust Boundary Violation
category: examples
---

# Trust Boundary Violation

**CWE-501** — Trust Boundary Violation.

Mixing trusted and untrusted data in the same structure — e.g. storing raw
request input directly into the HTTP session — blurs the line between data
the server can rely on and data the client controls, letting an attacker
smuggle values across that boundary.

## Vulnerable

```java
protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
    HttpSession session = req.getSession();
    // Trusts a client-supplied parameter as if it were server-verified.
    session.setAttribute("isAdmin", req.getParameter("isAdmin"));
}
```

An attacker submits `isAdmin=true` as a form field, and every later check
that reads `session.getAttribute("isAdmin")` treats it as a trusted,
server-decided flag — instantly privilege-escalating themselves.

## Fixed

```java
protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
    HttpSession session = req.getSession();
    User user = userService.load(session);
    // Server derives isAdmin from its own authoritative source, never the request.
    session.setAttribute("isAdmin", user.hasRole("ADMIN"));
}
```

The trust boundary is restored by deriving `isAdmin` from a server-side
lookup the client can't influence, instead of copying a client-supplied
parameter across it.
