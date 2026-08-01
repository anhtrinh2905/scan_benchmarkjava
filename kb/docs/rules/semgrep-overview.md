---
id: semgrep-overview
title: Semgrep in this repo's ablation (static arm)
category: rules
---

# Semgrep overview

[Semgrep](https://semgrep.dev) is a static analysis engine that matches
source code against declarative pattern rules (`pattern`, `pattern-either`,
etc. in YAML) without executing the code — it parses the AST and looks for
structural matches, so it can flag things like `new Random(...)` or
`$C.setSecure(false)` regardless of variable names or surrounding code.

**Role in this repo's ablation (`scripts/ablation.py`):** arm `static`
("C — Semgrep tìm, LLM chỉ verify" / engine `semgrep+metis`) runs Semgrep
first and has the LLM (via `metis --command "triage <sarif>"`) only verify
Semgrep's findings, rather than have the LLM search for vulnerabilities
itself. This isolates whether ablation performance comes from LLM reasoning
in the agent loop or from static analysis coverage.

**Rulesets used** (`SEMGREP_RULESETS` in `scripts/ablation.py`):
- `p/java` — Semgrep registry's general Java security ruleset.
- `p/owasp-top-ten` — Semgrep registry's OWASP Top 10 ruleset.
- `rules/benchmarkjava/` — this repo's custom rules (`weak-random.yaml`,
  `insecure-cookie.yaml`), covering patterns the registry rulesets don't.

**Output:** Semgrep writes SARIF (`semgrep.raw.sarif`), which
`normalize_semgrep_sarif` in `scripts/ablation.py` post-processes to inject a
`result.properties.cwe` field (extracted from the rule id/message, since
Semgrep leaves `properties` empty) before it's fed to the LLM triage step.
