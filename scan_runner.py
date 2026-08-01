"""Orchestration seam for the scan control panel (flow/05-contract.md).

Side-effects are limited to what the contract's Access/Effects column declares per
function (`start_run` spawns a subprocess; everything else is pure) — no `st.*`.
`app.py` is the only consumer.
"""
from __future__ import annotations

import csv
import importlib
import json
import os
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

ROOT = Path(__file__).resolve().parent
SCRIPTS_DIR = ROOT / "scripts"
RESULTS_ROOT = ROOT / "results"
RULES_DIR = ROOT / "rules" / "benchmarkjava"

SMOKE_SAMPLE_THRESHOLD = 10
LOG_TAIL_LINES = 40

READONLY_ENV_VAR = "SCAN_UI_READONLY"
_READONLY_TRUTHY = {"1", "true", "yes"}

# pid -> {"process": Popen, "log_path": Path} — outlives a single Streamlit rerun
# because this module stays imported for the life of the server process.
_RUN_REGISTRY: dict[int, dict] = {}

Kind = Literal["bench", "sweep", "ablation"]
RuntimeMode = Literal["local", "readonly"]


class ReadOnlyModeError(RuntimeError):
    """`start_run` was called on an instance that is not allowed to spawn scans."""

# kind -> (module, attr holding the known --only names); bench.py has no such
# dict — its --only is a free-text test-name substring filter, not a fixed set.
_ONLY_SOURCE = {
    "sweep": ("sweep", "VARIANTS"),
    "ablation": ("ablation", "ARMS"),
}


@dataclass
class CostEstimate:
    sample_count: int
    arms: list[str]
    warning_text: str


@dataclass
class RunHandle:
    pid: int
    command: list[str]
    started_at: str


@dataclass
class RunStatus:
    state: Literal["running", "done", "failed"]
    log_tail: str
    returncode: int | None


@dataclass
class RunSummary:
    name: str
    path: str
    modified_at: str


@dataclass
class RunMetrics:
    """Headline numbers for one run's KPI row (FR15). Every field is independently
    nullable: sweep/ablation arms record a strict subset of what bench does."""
    precision_strict: float | None = None
    recall_strict: float | None = None
    tp: int | None = None
    fp: int | None = None
    fn: int | None = None
    tn: int | None = None
    findings: int | None = None
    minutes: float | None = None
    total_tokens: int | None = None
    scan_model: str | None = None
    metis_version: str | None = None
    sample_size: int | None = None
    triage: bool | None = None
    generated_at: str | None = None


@dataclass
class ResultBundle:
    scorecard_md: str
    compare_rows: list[dict] | None
    cache_warning: str | None
    metrics: RunMetrics | None = None


@dataclass
class RunRef:
    """One scan run that carries per-test ground truth — a matrix column (FR14)."""
    kind: Kind
    name: str
    label: str
    path: str
    source: Literal["bench_summary", "detail"]
    test_count: int
    modified_at: str


@dataclass
class MatrixCell:
    outcome_strict: Literal["TP", "FP", "FN", "TN"]
    outcome_lenient: Literal["TP", "FP", "FN", "TN"]
    on_target: int
    off_target: int
    total: int
    inconclusive: int
    repeats: int


@dataclass
class MatrixRow:
    test: str
    category: str
    cwe: int | None
    expected_vulnerable: bool
    cells: dict[str, MatrixCell | None] = field(default_factory=dict)
    covered: int = 0
    detected: int = 0
    detection_rate: float = 0.0


@dataclass
class Matrix:
    runs: list[RunRef]
    rows: list[MatrixRow]
    total_cells: int
    coverage_note: str


def runtime_mode() -> RuntimeMode:
    """Whether this instance may spawn scans. Only an explicitly truthy
    `SCAN_UI_READONLY` locks it down: an unset or misspelled variable resolves to
    `"local"`, so a typo can never silently unlock scanning on a deployed host — it can
    only fail toward the mode that already existed before deploy mode was added."""
    return "readonly" if os.environ.get(READONLY_ENV_VAR, "").strip().lower() in _READONLY_TRUTHY else "local"


def known_only_values(kind: Kind) -> list[str]:
    """The fixed --only choices for kind, read from the script itself so the UI
    can never drift from what the script actually accepts. [] for bench."""
    source = _ONLY_SOURCE.get(kind)
    if source is None:
        return []
    module_name, attr = source
    sys.path.insert(0, str(SCRIPTS_DIR))
    try:
        module = importlib.import_module(module_name)
    finally:
        sys.path.remove(str(SCRIPTS_DIR))
    return list(getattr(module, attr))


def build_command(
    kind: Kind, only: list[str] | None, sample: int, tag: str | None = None
) -> list[str]:
    command = [f"./scripts/{kind}.py", "--sample", str(sample)]
    if kind == "bench" and tag:
        command += ["--tag", tag]
    if only:
        if kind == "bench":
            for value in only:
                command += ["--only", value]
        else:
            command += ["--only", *only]
    command.append("-y")
    return command


def estimate_cost(kind: Kind, sample: int, only: list[str] | None) -> CostEstimate:
    arms = list(only) if only else known_only_values(kind)
    warning_text = ""
    if sample > SMOKE_SAMPLE_THRESHOLD:
        scope = f" across {len(arms)} arm(s)/variant(s)" if arms else ""
        warning_text = (
            f"This will call a paid LLM {sample} time(s){scope} — confirm before running."
        )
    return CostEstimate(sample_count=sample, arms=arms, warning_text=warning_text)


def _output_dir_for(command: list[str]) -> Path:
    """Where this command's script writes results — bench.py's is `--tag`-named,
    sweep.py/ablation.py hardcode their top-level dir regardless of any flag."""
    kind = Path(command[0]).stem
    if kind != "bench":
        return RESULTS_ROOT / kind
    tag = "baseline"
    if "--tag" in command:
        tag = command[command.index("--tag") + 1]
    return RESULTS_ROOT / tag


def start_run(command: list[str]) -> RunHandle:
    """Spawn `command` in the background, log combined stdout/stderr to a file
    under its results dir, and return a handle `poll_run` can check on.

    Refuses outright in readonly mode. The check precedes every side-effect below —
    no directory, no log file, no process — because this function, not the UI control
    that usually calls it, is the boundary."""
    if runtime_mode() == "readonly":
        raise ReadOnlyModeError(
            "This instance runs in read-only mode and cannot start scans. "
            "Run the scan locally instead."
        )
    started_at = datetime.now(timezone.utc)
    out_dir = _output_dir_for(command)
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / f"ui-run-{started_at.strftime('%Y%m%dT%H%M%S%f')}.log"
    with log_path.open("w", encoding="utf-8") as log_file:
        process = subprocess.Popen(
            command, cwd=ROOT, stdout=log_file, stderr=subprocess.STDOUT
        )
    _RUN_REGISTRY[process.pid] = {"process": process, "log_path": log_path}
    return RunHandle(pid=process.pid, command=command, started_at=started_at.isoformat())


def poll_run(handle: RunHandle) -> RunStatus:
    """Non-blocking liveness + log-tail check for a handle from `start_run`."""
    entry = _RUN_REGISTRY.get(handle.pid)
    if entry is None:
        return RunStatus(state="failed", log_tail="", returncode=None)
    process: subprocess.Popen = entry["process"]
    log_path: Path = entry["log_path"]
    log_tail = ""
    if log_path.exists():
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        log_tail = "\n".join(lines[-LOG_TAIL_LINES:])
    returncode = process.poll()
    if returncode is None:
        state: Literal["running", "done", "failed"] = "running"
    elif returncode == 0:
        state = "done"
    else:
        state = "failed"
    return RunStatus(state=state, log_tail=log_tail, returncode=returncode)


def list_results(kind: Kind) -> list[RunSummary]:
    """Enumerate existing runs for kind. bench.py writes one scorecard.md-bearing
    dir per run directly under results/; sweep.py/ablation.py instead write one
    dir per variant/arm under results/<kind>/, sharing a single batch-level
    compare.csv rather than a scorecard per run."""
    if kind == "bench":
        run_dirs = [
            path
            for path in RESULTS_ROOT.iterdir()
            if path.is_dir()
            and path.name not in {"sweep", "ablation"}
            and (path / "scorecard.md").exists()
        ]
    else:
        kind_dir = RESULTS_ROOT / kind
        run_dirs = [path for path in kind_dir.iterdir() if path.is_dir()] if kind_dir.is_dir() else []
    summaries = [
        RunSummary(
            name=run_dir.name,
            path=str(run_dir.relative_to(ROOT)),
            modified_at=datetime.fromtimestamp(run_dir.stat().st_mtime, tz=timezone.utc).isoformat(),
        )
        for run_dir in run_dirs
    ]
    return sorted(summaries, key=lambda summary: summary.modified_at, reverse=True)


def _run_started_at(run_dir: Path) -> datetime:
    """Best-effort recorded start for run_dir, used as the FR6 staleness baseline.
    bench.py stamps `generated_at` in bench_summary.json; sweep.py/ablation.py
    stamp `ran_at` in runmeta.json. Derived arms with no run of their own (e.g.
    ablation's B_union_C, an offline union of two other arms) have neither file,
    so fall back to the dir's own mtime."""
    for filename, key in (("bench_summary.json", "generated_at"), ("runmeta.json", "ran_at")):
        meta_path = run_dir / filename
        if meta_path.exists():
            timestamp = json.loads(meta_path.read_text(encoding="utf-8")).get(key)
            if timestamp:
                return datetime.fromisoformat(timestamp)
    return datetime.fromtimestamp(run_dir.stat().st_mtime, tz=timezone.utc)


def _cache_warning_for(run_dir: Path) -> str | None:
    started_at = _run_started_at(run_dir)
    stale_rules = sorted(
        path.name
        for path in RULES_DIR.glob("*.yaml")
        if datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc) > started_at
    )
    if not stale_rules:
        return None
    return (
        f"Ruleset changed since this run started ({started_at.isoformat()}): "
        f"{', '.join(stale_rules)} updated more recently — results may be stale."
    )


def load_result(kind: Kind, name: str) -> ResultBundle:
    """Read one run's scorecard plus, for sweep/ablation, the batch-level compare
    table (shared across all variants/arms of that kind, since neither script
    writes a per-run scorecard), and compute the FR6 staleness signal."""
    if kind == "bench":
        run_dir = RESULTS_ROOT / name
        scorecard_path = run_dir / "scorecard.md"
        compare_rows = None
    else:
        run_dir = RESULTS_ROOT / kind / name
        scorecard_path = RESULTS_ROOT / kind / "compare.md"
        csv_path = RESULTS_ROOT / kind / "compare.csv"
        compare_rows = None
        if csv_path.exists():
            with csv_path.open(encoding="utf-8", newline="") as csv_file:
                compare_rows = list(csv.DictReader(csv_file))
    scorecard_md = scorecard_path.read_text(encoding="utf-8") if scorecard_path.exists() else ""
    return ResultBundle(
        scorecard_md=scorecard_md,
        compare_rows=compare_rows,
        cache_warning=_cache_warning_for(run_dir),
        metrics=_metrics_for(kind, run_dir),
    )


# --- v1.5: headline metrics (FR15) ------------------------------------------------

def _read_json(path: Path) -> dict:
    """Parse one run artifact, or {} if it isn't there / isn't readable JSON. A run
    directory is allowed to be incomplete — a half-written run must degrade the KPI row
    to "unknown", never raise past the seam into the page."""
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _section(data: dict, *keys: str) -> dict:
    """Walk nested run-artifact keys, treating a missing key AND an explicit JSON `null`
    as an empty section.

    `dict.get(key, {})` is not enough here: these artifacts write `null`, not omission,
    for a stage that did not run — `semgrep_stats` is null on the LLM-only ablation arms,
    and the arms that DO run semgrep write a dict. Both shapes are valid output from the
    same script, so every nested read on this side of the seam goes through here."""
    current = data
    for key in keys:
        value = current.get(key) if isinstance(current, dict) else None
        current = value if isinstance(value, dict) else {}
    return current


def _minutes(seconds: float | None) -> float | None:
    return round(seconds / 60.0, 1) if seconds else None


def _metrics_for(kind: Kind, run_dir: Path) -> RunMetrics | None:
    """The run's headline numbers, from whichever artifact its script wrote them to.
    bench.py puts everything in `bench_summary.json`; sweep.py/ablation.py split it
    between `detail.json` (scores, tokens) and `runmeta.json` (model, timestamp).
    Returns None only when the run kept no machine-readable summary at all."""
    if kind == "bench":
        summary = _read_json(run_dir / "bench_summary.json")
        if not summary:
            return None
        strict = _section(summary, "ground_truth", "strict")
        return RunMetrics(
            precision_strict=strict.get("precision"),
            recall_strict=strict.get("recall"),
            tp=strict.get("TP"),
            fp=strict.get("FP"),
            fn=strict.get("FN"),
            tn=strict.get("TN"),
            findings=summary.get("total_findings"),
            minutes=_minutes(summary.get("wall_clock_seconds")),
            total_tokens=_section(summary, "tokens").get("total_tokens"),
            scan_model=summary.get("scan_model"),
            metis_version=summary.get("metis_version"),
            sample_size=summary.get("sample_size"),
            triage=summary.get("triage"),
            generated_at=summary.get("generated_at"),
        )

    detail = _read_json(run_dir / "detail.json")
    meta = _read_json(run_dir / "runmeta.json")
    if not detail and not meta:
        return None
    strict = _section(detail, "ground_truth", "strict")
    per_test = _section(detail, "ground_truth", "per_test")
    usage = _section(detail, "usage") or _section(meta, "usage")
    return RunMetrics(
        precision_strict=strict.get("precision"),
        recall_strict=strict.get("recall"),
        tp=strict.get("TP"),
        fp=strict.get("FP"),
        fn=strict.get("FN"),
        tn=strict.get("TN"),
        # null on the arms that never invoke semgrep (prompt_only, harness) — those are
        # LLM-only by design, so "no semgrep finding count" is correct, not missing data.
        findings=_section(detail, "semgrep_stats").get("results"),
        minutes=_minutes(detail.get("wall_clock_seconds") or meta.get("wall_clock_seconds")),
        total_tokens=usage.get("total_tokens"),
        scan_model=_section(meta, "signature").get("scan_model"),
        metis_version=None,
        sample_size=len(per_test) or None,
        triage=_section(detail, "spec").get("triage"),
        generated_at=meta.get("ran_at"),
    )


# --- v1.5: cross-run matrix (FR14) ------------------------------------------------
#
# The matrix is derived on read, never persisted (ADR decision 21): 15 runs and ~700
# per-test records parse in milliseconds, and `results/` on disk stays the single source
# of truth. Two artifacts carry per-test ground truth and they are NOT the same shape:
# bench.py writes `bench_summary.json`, whose per_test entries hold `category`/`cwe` and a
# `runs[]` list (one entry per `--repeat`); sweep.py/ablation.py write `detail.json`, whose
# per_test entries are flat and carry no category at all. `_run_cells` normalizes both to
# MatrixCell so nothing above this line has to know which script produced a column.

OUTCOMES = ("TP", "FP", "FN", "TN")

# Tie-break order when repeat runs of the same test disagree — the first of these present
# among the tied outcomes wins. Pessimistic on purpose: a test that failed in half its
# repeats is reported as failing, never rounded up to a pass.
_TIE_BREAK = ("FN", "FP", "TN", "TP")

# A run "got this file right" when its strict outcome is a true positive or a true
# negative. detection_rate is over COVERED runs only — a run that never scanned the file
# is not evidence either way (ADR decision 22).
_CORRECT = {"TP", "TN"}


def _per_test_of(run_dir: Path, source: str) -> dict:
    filename = "bench_summary.json" if source == "bench_summary" else "detail.json"
    return _section(_read_json(run_dir / filename), "ground_truth", "per_test")


def list_all_runs() -> list[RunRef]:
    """Every run under `results/` that carries per-test ground truth, across all three
    kinds — the matrix's columns. A run directory holding neither `bench_summary.json`
    nor `detail.json` (a bare log dir, an arm that never finished) is skipped silently:
    it has nothing to contribute to a per-test table, and refusing to build the whole
    matrix because one arm is incomplete would be the wrong trade."""
    refs: list[RunRef] = []
    for kind in ("bench", "sweep", "ablation"):
        for summary in list_results(kind):  # type: ignore[arg-type]
            run_dir = ROOT / summary.path
            source = "bench_summary" if (run_dir / "bench_summary.json").exists() else "detail"
            per_test = _per_test_of(run_dir, source)
            if not per_test:
                continue
            refs.append(
                RunRef(
                    kind=kind,  # type: ignore[arg-type]
                    name=summary.name,
                    label=f"{kind}/{summary.name}",
                    path=summary.path,
                    source=source,  # type: ignore[arg-type]
                    test_count=len(per_test),
                    modified_at=summary.modified_at,
                )
            )
    return sorted(refs, key=lambda ref: (ref.kind, ref.name))


def _majority(outcomes: list[str]) -> str:
    """The modal outcome across a test's repeat runs, ties broken pessimistically."""
    counts = Counter(outcomes)
    top = max(counts.values())
    tied = [outcome for outcome, count in counts.items() if count == top]
    if len(tied) == 1:
        return tied[0]
    for candidate in _TIE_BREAK:
        if candidate in tied:
            return candidate
    return sorted(tied)[0]


def _cell_from_runs(runs: list[dict]) -> MatrixCell | None:
    """Collapse a bench per_test `runs[]` list (or a single flat detail.json entry
    wrapped in a list) into one cell: majority outcome, summed counts."""
    scored = [run for run in runs if run.get("outcome_strict") in OUTCOMES]
    if not scored:
        return None
    return MatrixCell(
        outcome_strict=_majority([run["outcome_strict"] for run in scored]),  # type: ignore[arg-type]
        outcome_lenient=_majority(
            [run.get("outcome_lenient", run["outcome_strict"]) for run in scored]
        ),  # type: ignore[arg-type]
        on_target=sum(run.get("on_target", 0) for run in scored),
        off_target=sum(run.get("off_target", 0) for run in scored),
        total=sum(run.get("total", 0) for run in scored),
        inconclusive=sum(run.get("inconclusive", 0) for run in scored),
        repeats=len(scored),
    )


def load_matrix(run_labels: list[str] | None = None) -> Matrix:
    """The per-file × per-run outcome matrix (FR14).

    Rows are the UNION of every test id seen in any included run, so the row set is the
    fixed 1..100 spine rather than one run's sample. A test a given run never scanned
    gets `None` for that column — never a synthesized `FN`, which would report a 6-file
    smoke run as having missed 94 vulnerabilities (ADR decision 22).

    Ground truth (`category`/`cwe`) is only recorded by bench runs, so it is gathered
    across all of them first; a test that appears only in sweep/ablation keeps
    `category="unknown"` rather than a guess."""
    runs = [ref for ref in list_all_runs() if run_labels is None or ref.label in run_labels]

    per_test_by_run: dict[str, dict] = {}
    truth: dict[str, dict] = {}
    for ref in runs:
        per_test = _per_test_of(ROOT / ref.path, ref.source)
        per_test_by_run[ref.label] = per_test
        for test, entry in per_test.items():
            known = truth.setdefault(test, {"category": None, "cwe": None, "expected": None})
            if known["category"] is None and entry.get("category"):
                known["category"] = entry["category"]
                known["cwe"] = entry.get("cwe")
            if known["expected"] is None:
                expected = entry.get("expected_vulnerable")
                if expected is None:
                    runs_list = entry.get("runs") or [entry]
                    expected = runs_list[0].get("expected") if runs_list else None
                known["expected"] = expected

    rows: list[MatrixRow] = []
    total_cells = 0
    for test in sorted(truth):
        known = truth[test]
        row = MatrixRow(
            test=test,
            category=known["category"] or "unknown",
            cwe=known["cwe"],
            expected_vulnerable=bool(known["expected"]),
        )
        for ref in runs:
            entry = per_test_by_run[ref.label].get(test)
            cell = _cell_from_runs(entry.get("runs") or [entry]) if entry else None
            row.cells[ref.label] = cell
            if cell is not None:
                total_cells += 1
                row.covered += 1
                if cell.outcome_strict in _CORRECT:
                    row.detected += 1
        row.detection_rate = row.detected / row.covered if row.covered else 0.0
        rows.append(row)

    return Matrix(
        runs=runs,
        rows=rows,
        total_cells=total_cells,
        coverage_note=_coverage_note(runs),
    )


def _coverage_note(runs: list[RunRef]) -> str:
    """Non-empty whenever the included runs scanned different numbers of tests — which is
    the normal case here (6 to 100). The UI shows this verbatim so a reader cannot mistake
    an unscanned cell for a missed detection."""
    if not runs:
        return ""
    counts = [ref.test_count for ref in runs]
    low, high = min(counts), max(counts)
    if len(runs) == 1:
        return f"`{runs[0].label}` scanned {high} test files."
    if low == high:
        return f"All {len(runs)} runs scanned the same {high} test files."
    thinnest = min(runs, key=lambda ref: ref.test_count)
    widest = max(runs, key=lambda ref: ref.test_count)
    return (
        f"These {len(runs)} runs cover different subsets — from {low} files "
        f"(`{thinnest.label}`) to {high} files (`{widest.label}`). "
        "An empty cell means that run never scanned that file. It does not mean a miss."
    )


def matrix_categories(matrix: Matrix) -> list[str]:
    """The distinct categories present, for populating a filter control without the UI
    scanning rows itself."""
    return sorted({row.category for row in matrix.rows})


def filter_matrix(
    matrix: Matrix,
    query: str = "",
    categories: list[str] | None = None,
    kinds: list[str] | None = None,
    run_labels: list[str] | None = None,
    outcomes: list[str] | None = None,
    only_disputed: bool = False,
) -> Matrix:
    """Narrow the matrix in BOTH dimensions (FR14's search). Pure — no I/O, no
    Streamlit — so the searchable behaviour is testable on its own.

    `kinds` and `run_labels` pick the columns; everything else picks the rows. Narrowing
    columns rather than only rows is what makes "show me the ablation runs" mean what a
    reader expects — and at 15 runs it is also the only way to get a comparison of three
    of them onto one screen.

    `covered`/`detected`/`detection_rate` are recomputed against the surviving columns:
    a hit rate that still counted hidden runs would describe a table the reader cannot
    see. Facets combine with AND; an empty/None facet is "no constraint"."""
    needle = query.strip().lower()
    runs = [
        ref for ref in matrix.runs
        if (not kinds or ref.kind in kinds) and (not run_labels or ref.label in run_labels)
    ]
    labels = [ref.label for ref in runs]

    rows: list[MatrixRow] = []
    for row in matrix.rows:
        if needle and needle not in " ".join(
            (row.test, row.category, f"cwe-{row.cwe}" if row.cwe else "")
        ).lower():
            continue
        if categories and row.category not in categories:
            continue

        cells = {label: row.cells.get(label) for label in labels}
        scored = [cell for cell in cells.values() if cell is not None]
        if not scored:
            continue
        if outcomes and not any(cell.outcome_strict in outcomes for cell in scored):
            continue
        correct = sum(1 for cell in scored if cell.outcome_strict in _CORRECT)
        if only_disputed and correct in (0, len(scored)):
            continue

        rows.append(
            MatrixRow(
                test=row.test,
                category=row.category,
                cwe=row.cwe,
                expected_vulnerable=row.expected_vulnerable,
                cells=cells,
                covered=len(scored),
                detected=correct,
                detection_rate=correct / len(scored),
            )
        )

    return Matrix(
        runs=runs,
        rows=rows,
        total_cells=sum(1 for row in rows for cell in row.cells.values() if cell),
        coverage_note=_coverage_note(runs),
    )


def matrix_records(matrix: Matrix, strict: bool = True) -> list[dict]:
    """One flat, DataFrame-ready dict per row. Values are display-ready strings and
    plain numbers so the same records drive both the on-screen table and the CSV
    download with no second formatting pass:

      test str · category str · cwe "CWE-22"|"" · expected "vulnerable"|"safe" ·
      covered int · detected int · detection_rate float · <run label> "TP"|"FP"|"FN"|"TN"|""

    An unscanned cell is the empty string, not "N/A" and not a zero — it reads as absent
    in the table and stays absent in the exported CSV."""
    records: list[dict] = []
    for row in matrix.rows:
        record: dict = {
            "test": row.test,
            "category": row.category,
            "cwe": f"CWE-{row.cwe}" if row.cwe else "",
            "expected": "vulnerable" if row.expected_vulnerable else "safe",
            "covered": row.covered,
            "detected": row.detected,
            "detection_rate": round(row.detection_rate, 3),
        }
        for ref in matrix.runs:
            cell = row.cells.get(ref.label)
            if cell is None:
                record[ref.label] = ""
            else:
                record[ref.label] = cell.outcome_strict if strict else cell.outcome_lenient
        records.append(record)
    return records
