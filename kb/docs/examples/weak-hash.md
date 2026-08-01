---
id: weak-hash
title: Weak Hash for Password Storage
category: examples
---

# Weak Hash for Password Storage

**CWE-327** — Use of a Broken or Risky Cryptographic Algorithm.

Hashing passwords with a fast, unsalted general-purpose digest (MD5, SHA-1)
lets an attacker who steals the database recover passwords quickly via
precomputed rainbow tables or brute-force GPU cracking.

## Vulnerable

```java
public String hashPassword(String password) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance("MD5");
    byte[] digest = md.digest(password.getBytes(StandardCharsets.UTF_8));
    return Base64.getEncoder().encodeToString(digest);
}
```

MD5 has no per-user salt and is fast by design, so a stolen table of hashes
can be cracked in bulk against rainbow tables or a GPU brute-forcer in
minutes.

## Fixed

```java
public String hashPassword(String password) {
    // BCrypt generates and stores its own random salt inside the output hash.
    return BCrypt.hashpw(password, BCrypt.gensalt(12));
}
```

A slow, salted password-hashing function (BCrypt/Argon2/scrypt) makes each
guess computationally expensive and unique per user, defeating both
precomputed tables and bulk GPU cracking.
