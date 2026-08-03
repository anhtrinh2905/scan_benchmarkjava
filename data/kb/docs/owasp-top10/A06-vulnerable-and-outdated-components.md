---
id: A06
title: Vulnerable and Outdated Components
category: owasp-top10
---

# A06:2021 — Vulnerable and Outdated Components

Using libraries, frameworks, or other components with known vulnerabilities,
or components that are unsupported/out of date. This was previously "Using
Components with Known Vulnerabilities" and remains hard to test directly but
easy to exploit once a public CVE exists for a dependency in use.

**Why it matters:** the vulnerable code isn't even yours — an attacker only
needs to know which library version you ship and reuse an existing public
exploit, no discovery required on their part.

**Example:** an application bundling an old version of a JSON or XML parsing
library with a known deserialization CVE can be compromised simply by
sending a crafted payload to any endpoint that parses attacker-supplied
input with that library.
