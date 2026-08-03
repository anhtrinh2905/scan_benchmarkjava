---
id: A02
title: Cryptographic Failures
category: owasp-top10
---

# A02:2021 — Cryptographic Failures

Formerly "Sensitive Data Exposure," this category covers failures related to
cryptography (or its absence) that lead to exposure of sensitive data: no
encryption in transit or at rest, weak/outdated algorithms, hard-coded keys,
or weak random-number generation used for security-sensitive values.

**Why it matters:** even a well-access-controlled system leaks everything if
the data itself isn't protected — passwords, session tokens, and PII become
plaintext-equivalent the moment a weak cipher, a predictable PRNG, or a
missing TLS config is in the path.

**Example:** generating a password-reset token with `java.util.Random`
instead of `java.security.SecureRandom` makes the token guessable, letting an
attacker predict or brute-force it and take over another user's account.
