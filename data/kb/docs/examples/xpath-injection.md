---
id: xpath-injection
title: XPath Injection
category: examples
---

# XPath Injection

**CWE-643** — Improper Neutralization of Data within XPath Expressions.

Concatenating untrusted input into an XPath expression evaluated against an
XML document lets an attacker alter the query's logic, similarly to SQL or
LDAP injection but against XML data instead of a database.

## Vulnerable

```java
public boolean login(Document usersXml, String user, String pass)
        throws XPathExpressionException {
    XPath xpath = XPathFactory.newInstance().newXPath();
    String expr = "//user[username/text()='" + user
        + "' and password/text()='" + pass + "']";
    NodeList nodes = (NodeList) xpath.evaluate(expr, usersXml, XPathConstants.NODESET);
    return nodes.getLength() > 0;
}
```

Input `user = "' or '1'='1"` turns the predicate into an always-true
condition, matching the first `user` node in the document regardless of the
real password.

## Fixed

```java
public boolean login(Document usersXml, String user, String pass)
        throws XPathExpressionException {
    XPath xpath = XPathFactory.newInstance().newXPath();
    xpath.setXPathVariableResolver(v -> "user".equals(v.getLocalPart()) ? user : pass);
    String expr = "//user[username/text()=$user and password/text()=$pass]";
    NodeList nodes = (NodeList) xpath.evaluate(expr, usersXml, XPathConstants.NODESET);
    return nodes.getLength() > 0;
}
```

Binding `user`/`pass` as XPath variables (rather than splicing them into the
expression string) keeps attacker input as literal string data the
expression compares against, not executable query syntax.
