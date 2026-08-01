---
id: weak-prng
title: Weak PRNG for a Security Token
category: examples
---

# Weak PRNG for a Security Token

**CWE-330** — Use of Insufficiently Random Values.

Flagged by this repo's `benchmarkjava.weak-prng.*` rules
([doc](../rules/weak-random.md)). Using a non-cryptographic PRNG to generate
a value meant to be unguessable (tokens, reset codes, session IDs) lets an
attacker predict or brute-force it.

## Vulnerable

```java
public String generateResetToken() {
    Random rnd = new Random();
    return Long.toHexString(rnd.nextLong());
}
```

`java.util.Random` is seeded from a 48-bit value and its output sequence is
fully predictable once a few outputs are observed, so an attacker who sees
one issued token can compute past or future ones.

## Fixed

```java
public String generateResetToken() {
    SecureRandom rnd = new SecureRandom();
    byte[] bytes = new byte[24];
    rnd.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
}
```

`SecureRandom` draws from a cryptographically secure source, so observing
past outputs gives an attacker no advantage in predicting future ones.
