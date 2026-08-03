---
id: A09
title: Security Logging and Monitoring Failures
category: owasp-top10
---

# A09:2021 — Security Logging and Monitoring Failures

Insufficient logging, detection, monitoring, and incident response — auditable
events (logins, failed access attempts, high-value transactions) not logged,
or logs that exist but no one alerts on them. Doesn't stop an initial breach,
but its absence is what lets a breach go unnoticed for months.

**Why it matters:** without logging and alerting, a successful attack is
indistinguishable from normal traffic — breaches are typically found by an
external party long after the actual damage, if they're found at all.

**Example:** an application that logs application errors but never logs
failed login attempts gives no signal when an attacker is brute-forcing
credentials against it in real time — there's nothing to alert on.
