---
id: ldap-injection
title: LDAP Injection
category: examples
---

# LDAP Injection

**CWE-90** — Improper Neutralization of Special Elements used in an LDAP Query.

Concatenating untrusted input into an LDAP filter string lets an attacker
alter the filter's logic — e.g. bypassing an authentication check or
widening a search to return records they shouldn't see.

## Vulnerable

```java
public boolean authenticate(DirContext ctx, String user, String pass)
        throws NamingException {
    String filter = "(&(uid=" + user + ")(userPassword=" + pass + "))";
    NamingEnumeration<SearchResult> results =
        ctx.search("ou=people,dc=example,dc=com", filter, new SearchControls());
    return results.hasMore();
}
```

Input `user = "*)(uid=*))(|(uid=*"` rewrites the filter's boolean structure
so the query matches regardless of the real password, authenticating as an
arbitrary user.

## Fixed

```java
public boolean authenticate(DirContext ctx, String user, String pass)
        throws NamingException {
    String filter = "(&(uid={0})(userPassword={1}))";
    Object[] args = { user, pass };
    NamingEnumeration<SearchResult> results = ctx.search(
        "ou=people,dc=example,dc=com", filter, args, new SearchControls());
    return results.hasMore();
}
```

`DirContext.search` with a parameterized filter and an args array escapes
each value for LDAP filter syntax before substitution, so special
characters like `*`, `(`, `)` can't change the filter's structure.
