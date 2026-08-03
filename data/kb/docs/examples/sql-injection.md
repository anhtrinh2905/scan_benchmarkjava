---
id: sql-injection
title: SQL Injection
category: examples
---

# SQL Injection

**CWE-89** — Improper Neutralization of Special Elements used in an SQL Command.

Building a SQL query by concatenating untrusted input lets an attacker alter
the query's structure — bypassing filters, exfiltrating other tables, or
modifying data.

## Vulnerable

```java
public User findByName(Connection conn, String name) throws SQLException {
    Statement stmt = conn.createStatement();
    String sql = "SELECT * FROM users WHERE name = '" + name + "'";
    ResultSet rs = stmt.executeQuery(sql);
    return rs.next() ? mapUser(rs) : null;
}
```

Input `' OR '1'='1' --` turns the query into
`SELECT * FROM users WHERE name = '' OR '1'='1' --'`, returning every row.

## Fixed

```java
public User findByName(Connection conn, String name) throws SQLException {
    String sql = "SELECT * FROM users WHERE name = ?";
    PreparedStatement stmt = conn.prepareStatement(sql);
    stmt.setString(1, name);
    ResultSet rs = stmt.executeQuery();
    return rs.next() ? mapUser(rs) : null;
}
```

A parameterized query sends `name` as data, never as part of the SQL text,
so it can't change the query's structure.
