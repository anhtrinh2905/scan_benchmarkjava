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
from dataclasses import dataclass
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
class ResultBundle:
    scorecard_md: str
    compare_rows: list[dict] | None
    cache_warning: str | None


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
    )
