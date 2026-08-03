---
id: A08
title: Software and Data Integrity Failures
category: owasp-top10
---

# A08:2021 — Software and Data Integrity Failures

A new 2021 category about code and infrastructure that doesn't verify
integrity before trusting it: unsigned/unverified software updates, CI/CD
pipelines that pull unvetted dependencies, or insecure deserialization of
data whose origin and structure aren't validated.

**Why it matters:** these failures let an attacker tamper with something the
application implicitly trusts — an update, a plugin, or a serialized object —
and turn that trust into arbitrary code execution.

**Example:** deserializing an untrusted Java object stream with
`ObjectInputStream.readObject()` without type restrictions lets an attacker
craft a gadget-chain payload that executes arbitrary code the moment it's
deserialized.
