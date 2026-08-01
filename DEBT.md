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

- **2026-08-01 — a scan that never reached the model is indistinguishable from a clean
  scan in every results surface.** `deepseek-v4-flash` began returning HTTP 403
  `RegionError` ("only available hosted in China and requires explicit opt in"). Metis
  swallowed the error, wrote `reviews: []` for every file and **exited 0**, so
  `sweep.py` recorded three variants (`baseline`, `workers_10`, `reach_1`) as valid runs
  with 0 findings and 0% recall. The scorecard, the compare table and the new Matrix page
  all rendered them as legitimate all-miss results; nothing on any surface said "this run
  spent 0 tokens in 10 seconds". Found only by comparing token counts across runs by hand.
  **Deferred fix:** flag a run whose `usage.total_tokens == 0` while `len(per_test) > 0`
  — at minimum a warning on Results and a marker column in the Matrix, ideally a non-zero
  exit from `bench.py`/`sweep.py` so the harness itself refuses to score it. Not fixed in
  C-014, whose allowed files exclude `scripts/*.py`. Interim mitigation: the three runs
  were re-run on `deepseek-v4-pro` and `.env` now pins that model, so the specific 403 is
  gone — but the silent-failure hole it exposed is still open for the next dead model.

- **2026-08-01 — the progress bar (FR16) cannot move live on a run of 2 test files,
  because one `print` in `bench.py` is missing `flush=True`.** `bench.py:859` and `:890`
  both flush their `[N/M]` lines, but `:865` — the smoke test's completion,
  `    -> strict=TP  lenient=TP  (3 finding)` — does not. Python block-buffers stdout when
  it is a pipe rather than a TTY (which is exactly how `start_run` captures it), so that
  line does not reach the log until the process exits. Consequence: at `--sample 2` the
  only live signals are the smoke *start* (0/2) and the final completion (2/2), and the
  bar appears frozen for the whole run; at `--sample >= 3` the flushed `[k/M]` completions
  make it move normally. Confirmed on two real runs (`results/c015_progress`,
  `results/c015_bar`): both logs contain the 1/2 state, and `parse_progress` reads it
  correctly — but only after exit. **Fix is one keyword argument** (`flush=True` on
  `bench.py:865`); deliberately not applied in C-015, whose allowed files exclude
  `scripts/*.py` and whose whole premise (ADR 23) is that the scripts stay byte-identical.
  Worth a small dedicated card with the standard 0-regression check.
