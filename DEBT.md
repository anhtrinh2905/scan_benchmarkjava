# Debt ledger

Deliberate exposures and deferred fixes, accepted in writing. One line each, dated.

- **2026-08-01 — deployed instance is public with no access control at all.**
  `https://scan-benchmarkjava-production.up.railway.app` serves the Results and Knowledge
  Base pages to anyone, and the password gate shipped in C-012 was removed from the code
  rather than merely disabled (ADR 19, card C-013). Operator accepted the exposure after
  review: what becomes permanently public is the benchmark scorecards (scan model
  `deepseek-v4-flash`, Metis version, wall-clock and token counts, precision/recall) plus
  public OWASP documentation. Verified absent: any credential-shaped string — the
  `password`/`secret` matches inside `results/` are BenchmarkJava vulnerability
  descriptions, not keys. The URL is search-engine indexable; a `noindex` option was
  offered and not taken. Containment is ADR 14, not secrecy: the instance cannot start a
  scan and holds no `OPENCODE_API_KEY`. **Re-gating later requires re-adding code**, since
  the mechanism is gone rather than switched off.
