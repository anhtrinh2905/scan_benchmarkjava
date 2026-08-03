---
id: A07
title: Identification and Authentication Failures
category: owasp-top10
---

# A07:2021 — Identification and Authentication Failures

Formerly "Broken Authentication," covering weaknesses in confirming a user's
identity: permitting weak or default passwords, allowing credential
stuffing/brute force without rate limiting, exposing session IDs in the URL,
or failing to invalidate sessions properly.

**Why it matters:** authentication is the gate every other control sits
behind — if an attacker can impersonate a legitimate user, access control,
encryption, and logging all become irrelevant for that session.

**Example:** a login endpoint with no rate limiting or account lockout lets
an attacker script thousands of password guesses per minute against a single
username until one succeeds (credential stuffing/brute force).
