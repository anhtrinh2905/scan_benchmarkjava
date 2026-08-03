---
id: weak-random
title: Weak PRNG (weak-random)
category: rules
---

# Rule: `benchmarkjava.weak-prng.*`

Defined in `rules/benchmarkjava/weak-random.yaml`. Flags two patterns:
`new java.util.Random(...)` / `new Random(...)` (`benchmarkjava.weak-prng.util-random`)
and `Math.random(...)` / `java.lang.Math.random(...)`
(`benchmarkjava.weak-prng.math-random`).

**What it flags:** use of a statistically-predictable pseudo-random number
generator anywhere in the scanned code, regardless of what the generated
value is used for.

**CWE:** CWE-330 — Use of Insufficiently Random Values.

**Why it's a finding:** `java.util.Random` and `Math.random()` are seeded
PRNGs designed for speed, not unpredictability — their output can be
predicted or reproduced by an attacker who observes a few outputs or knows
the approximate seed time. That's fine for jitter/backoff timings, but unsafe
for anything security-sensitive: tokens, password-reset codes, session IDs,
API keys.

**Fix:**

```java
// Before — CWE-330
Random rnd = new Random();
String token = Long.toHexString(rnd.nextLong());

// After
SecureRandom rnd = new SecureRandom();
byte[] bytes = new byte[16];
rnd.nextBytes(bytes);
String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
```
