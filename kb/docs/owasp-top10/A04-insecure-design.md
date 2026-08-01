---
id: A04
title: Insecure Design
category: owasp-top10
---

# A04:2021 — Insecure Design

A new 2021 category focused on risks rooted in design and architecture
rather than implementation bugs — missing threat modeling, missing business-
logic limits, or trusting the client to enforce rules the server should
enforce. No amount of clean coding fixes a design that was never secure to
begin with.

**Why it matters:** implementation-level fixes (input validation, escaping)
can't patch a flaw baked into the flow itself — the system does exactly what
it was designed to do, and that design allows abuse.

**Example:** an e-commerce checkout that computes the final price client-side
and simply trusts the value the browser submits back, instead of
recalculating it server-side from cart contents, lets an attacker submit any
price they like.
