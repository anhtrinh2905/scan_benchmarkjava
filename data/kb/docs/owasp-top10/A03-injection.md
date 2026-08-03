---
id: A03
title: Injection
category: owasp-top10
---

# A03:2021 — Injection

Injection happens when untrusted input is concatenated into a command,
query, or interpreter without separation between data and code — SQL, OS
command, LDAP, and XPath injection all fall under this one category, along
with cross-site scripting (XSS), which OWASP folded in for 2021.

**Why it matters:** injection flaws are directly exploitable and often give
an attacker the same power as the application itself — reading or altering
an entire database, running arbitrary shell commands, or executing script in
another user's browser session.

**Example:** building a query with
`"SELECT * FROM users WHERE name = '" + userInput + "'"` lets an attacker
supply `' OR '1'='1` to bypass the intended filter and dump the whole table.
