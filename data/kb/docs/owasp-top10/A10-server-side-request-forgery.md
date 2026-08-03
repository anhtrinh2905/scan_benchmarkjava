---
id: A10
title: Server-Side Request Forgery (SSRF)
category: owasp-top10
---

# A10:2021 — Server-Side Request Forgery (SSRF)

SSRF occurs when an application fetches a remote resource using a
user-supplied URL without validating or restricting the destination,
letting an attacker make the server issue requests it never intended to —
including to internal-only services.

**Why it matters:** the request originates from the trusted server itself,
so it can reach internal networks, cloud metadata endpoints, or admin
interfaces that are normally unreachable from the outside — turning a simple
URL parameter into an internal network foothold.

**Example:** an image-upload feature that fetches
`GET /fetch?url=<user-supplied-url>` server-side without restricting the
target lets an attacker point it at `http://169.254.169.254/` to read cloud
instance metadata, including credentials.
