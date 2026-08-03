---
id: A05
title: Security Misconfiguration
category: owasp-top10
---

# A05:2021 — Security Misconfiguration

Covers missing hardening across any layer of the stack: default credentials
left in place, unnecessary features or ports enabled, verbose error messages
that leak stack traces, permissive CORS, or cloud storage left open. This
category moved up from #6 in the 2017 list as misconfiguration became one of
the most tested-for issues.

**Why it matters:** misconfiguration is easy to introduce (a default left
unchanged, a debug flag never turned off in prod) and easy for an attacker to
find with automated scanning — it's often the lowest-effort path in.

**Example:** shipping a Java servlet container with directory listing
enabled lets an attacker browse `/WEB-INF/` or backup files and read
configuration, credentials, or source directly.
