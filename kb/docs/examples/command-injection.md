---
id: command-injection
title: OS Command Injection
category: examples
---

# OS Command Injection

**CWE-78** — Improper Neutralization of Special Elements used in an OS Command.

Passing untrusted input to a shell interpreter lets an attacker append their
own commands, gaining the same privileges the application process has on the
host.

## Vulnerable

```java
public void pingHost(String host) throws IOException {
    Runtime.getRuntime().exec("ping -c 1 " + host);
}
```

Input `example.com; rm -rf /tmp/data` runs the intended `ping` and then the
attacker's injected `rm` command, since `exec` here hands the whole string to
a shell.

## Fixed

```java
public void pingHost(String host) throws IOException {
    if (!host.matches("[a-zA-Z0-9.-]+")) {
        throw new IllegalArgumentException("invalid host");
    }
    new ProcessBuilder("ping", "-c", "1", host).start();
}
```

`ProcessBuilder` with a pre-split argument array passes `host` as a single
literal argument (no shell parses it for `;`/`|`/`&&`), and the allow-list
regex rejects anything that isn't a plain hostname before it ever reaches
`exec`.
