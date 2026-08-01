---
id: A01
title: Broken Access Control
category: owasp-top10
---

# A01:2021 — Broken Access Control

Access control enforces that a user can act only within their intended
permissions. Broken access control means those checks are missing, wrong, or
bypassable — the most common category in the 2021 OWASP Top 10 (94% of tested
apps had some form of it).

**Why it matters:** a failure here lets an attacker act as another user, read
or modify data they shouldn't touch, or reach admin functionality outright —
it undermines every other security control built on top of "you are who you
say you are."

**Example:** an endpoint like `GET /accounts/{id}/invoices` that trusts the
`id` path parameter without checking it belongs to the authenticated caller
(insecure direct object reference) lets any logged-in user read anyone else's
invoices by changing the number in the URL.
