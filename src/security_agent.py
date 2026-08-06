"""Security Analysis Agent — deterministic core (flow/05-contract.md, v1.7 increment).

Library-style seam, the same shape as `alert_normalizer.py` / `kb_search.py`: flat
imports, no Streamlit, no CLI flag parsing, no process termination. Everything in this
file runs offline; the one bounded model call and the versioned prompt file (ADR 24/25/28)
arrive in C-017, and `analyze()` refuses that path until then.

The pipeline is fixed and one-directional (ADR 24):

    load_alerts -> group_alerts -> attach_kb -> analyze_group -> build_finding -> write_report
      (I/O)         (pure)         (read-only)  (C-017)          (pure)          (side-effect)

Two properties carry the honesty guarantees this module exists for:

* **Conservation** — `sum(occurrence_count) + sum(exact_duplicates_removed) == len(alerts)`
  is asserted in `group_alerts()`, and `AnalysisMeta.accounted_for` extends it across the
  skipped lines. Nothing can be dropped without the arithmetic saying so.
* **Byte-stability** — every run-scoped value (timestamps, token counts, durations) lives
  in the `report.meta.json` sidecar, never in `report.jsonl` (ADR 31), so two identical
  offline runs produce identical finding bytes.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal

import requests

import kb_search
from alert_normalizer import (
    KB_ALERTS_PATH,
    SEVERITIES,
    Alert,
    normalize_bench_summary,
    normalize_sarif,
)

ROOT = Path(__file__).resolve().parent.parent
RESULTS_ROOT = ROOT / "data" / "results"
ANALYSIS_DIR = ROOT / "data" / "analysis"
# Inside src/ deliberately: `.dockerignore` excludes /docs/, so a prompt kept there would
# be missing from the deployed image (ADR 28). It is source, and is reviewed like source.
PROMPT_PATH = ROOT / "src" / "prompts" / "security_analyst.md"

REPORT_FILENAME = "report.jsonl"
META_FILENAME = "report.meta.json"

CHAT_ROUTE = "/chat/completions"
CALL_TIMEOUT_SECONDS = 60

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]
AnalysisStatus = Literal["ok", "empty", "invalid_input", "degraded"]
AnalysisSource = Literal["llm", "fallback"]

CONFIDENCES = ("high", "medium", "low")

# Ordered low-to-high so a rank difference is a signed distance the clamp can reason about.
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_RANK_TO_SEVERITY = {rank: name for name, rank in SEVERITY_RANK.items()}

TOOLS = ("semgrep", "metis")

# Every key an Alert record must carry. The three nullable ones still have to be PRESENT —
# a record that simply omits `cwe` is malformed, not a record with an unknown CWE.
_ALERT_TEXT_FIELDS = ("tool", "severity", "file_or_url", "title", "description", "source_path")
_ALERT_NULLABLE_TEXT_FIELDS = ("rule_id", "cwe")
_ALERT_NULLABLE_INT_FIELDS = ("line",)

RAW_LINE_LIMIT = 200
FALLBACK_KB_EXCERPT_CHARS = 700

# The reason recorded on every finding produced by an explicitly offline run. A model
# failure passes its own closed-set reason instead (contract: GroupAnalysis.failure_reason).
NO_LLM_REASON = "phân tích ngoại tuyến được yêu cầu (--no-llm)"
# Groups past --limit are never sent to the model, but they still become findings, which is
# what keeps the report's own arithmetic true under a cost cap.
LIMIT_REASON = "nhóm này nằm ngoài --limit nên không được gửi tới mô hình"

# The closed failure set (contract v1.7). A counted reason beats a grepped one.
FAILURE_REASONS = (
    "transport_error",
    "http_error",
    "empty_response",
    "zero_tokens",
    "non_json",
    "schema_invalid",
    "retry_exhausted",
)

_MODEL_FINDING_TEXT_KEYS = (
    "title_vi",
    "explanation_vi",
    "how_to_verify_vi",
    "how_to_fix_vi",
    "severity_rationale_vi",
)
_MODEL_FINDING_KEYS = frozenset(
    _MODEL_FINDING_TEXT_KEYS + ("code_hint", "severity", "confidence", "kb_doc_ids")
)
TITLE_MAX_CHARS = 120

_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.DOTALL)
_PROMPT_FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n?(.*)$", re.DOTALL)

logger = logging.getLogger(__name__)

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_SECTION_RE_TEMPLATE = r"^##\s+{heading}\s*$(.*?)(?=^##\s|\Z)"


class PromptMissingError(RuntimeError):
    """No prompt file to run with — the agent never falls back to an implicit built-in
    prompt (ADR 28). Raised by `load_system_prompt()`, which lands in C-017."""


class ReportCorruptError(RuntimeError):
    """A findings line will not parse. Better than silently rendering a partial report."""


# --- shapes (flow/05-contract.md, v1.7) -------------------------------------------


@dataclass
class SystemPrompt:
    text: str
    path: str
    sha256: str
    version: str


@dataclass
class ModelFinding:
    """What the model is allowed to say. Note what is absent: no file, no line, no rule id,
    no CWE. Those are facts about the scan, filled in by code from the alerts themselves
    (FR18 NFR), and anything the model writes about them is discarded."""

    title_vi: str
    explanation_vi: str
    how_to_verify_vi: str
    how_to_fix_vi: str
    code_hint: str | None
    severity: str
    severity_rationale_vi: str
    confidence: str
    kb_doc_ids: list[str]


@dataclass
class GroupAnalysis:
    ok: bool
    finding: ModelFinding | None = None
    failure_reason: str | None = None
    failure_detail: str = ""
    model: str | None = None
    total_tokens: int = 0
    calls: int = 0
    dropped_kb_ids: int = 0


@dataclass
class AnalysisEstimate:
    group_count: int
    call_count: int
    model: str
    warning_text: str


@dataclass
class SkippedRecord:
    line_no: int
    reason: str
    raw: str


@dataclass
class AlertLoad:
    alerts: list[Alert]
    skipped: list[SkippedRecord]
    lines_read: int
    source: str


@dataclass
class AlertRef:
    file_or_url: str
    line: int | None
    tool: str
    rule_id: str | None


@dataclass
class AlertGroup:
    group_key: str
    cwe: str | None
    rule_family: str
    title: str
    tool_severity: str
    tools: list[str]
    occurrences: list[AlertRef]
    occurrence_count: int
    exact_duplicates_removed: int
    descriptions: list[str]
    source_paths: list[str]


@dataclass
class Location:
    file: str
    line: int | None
    tool: str


@dataclass
class Evidence:
    tool: str
    rule_id: str | None
    raw_message: str
    occurrence_count: int
    files_affected: int
    source_paths: list[str]


@dataclass
class Remediation:
    how_to_verify: str
    how_to_fix: str
    code_hint: str | None


@dataclass
class SeverityDecision:
    severity: str
    clamped: bool
    distance: int


@dataclass
class ConfidenceDecision:
    confidence: str
    reason: str


@dataclass
class Finding:
    finding_id: str
    title: str
    severity: str
    severity_source: str
    severity_rationale: str
    severity_clamped: bool
    cwe: str | None
    owasp: str | None
    locations: list[Location]
    evidence: Evidence
    explanation: str
    remediation: Remediation
    confidence: str
    confidence_reason: str
    kb_refs: list[str]
    analysis_source: str
    model: str | None
    prompt_sha256: str


@dataclass
class AnalysisMeta:
    status: str
    generated_at: str
    input_source: str
    alerts_read: int
    alerts_valid: int
    alerts_skipped: int
    skipped: list[SkippedRecord]
    exact_duplicates_removed: int
    groups: int
    findings: int
    accounted_for: bool
    limit_applied: int | None
    llm_calls: int
    llm_failures: int
    llm_failure_reasons: dict[str, int]
    dropped_kb_ids: int
    total_tokens: int | None
    model: str | None
    prompt_path: str
    prompt_sha256: str
    prompt_version: str
    duration_seconds: float


@dataclass
class AnalysisReport:
    findings: list[Finding]
    meta: AnalysisMeta


@dataclass
class WriteResult:
    jsonl_path: str
    meta_path: str
    findings_written: int


# --- load (FR17, FR21 scenarios 1 and 2) ------------------------------------------


def _relative(path: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def _validate_alert(record: dict) -> tuple[Alert | None, str]:
    """A record either becomes an Alert or names exactly why it could not, using the
    contract's closed reason wording so the sidecar can be counted rather than grepped."""
    for name in _ALERT_TEXT_FIELDS + _ALERT_NULLABLE_TEXT_FIELDS + _ALERT_NULLABLE_INT_FIELDS:
        if name not in record:
            return None, f"missing field: {name}"
    for name in _ALERT_TEXT_FIELDS:
        if not isinstance(record[name], str):
            return None, f"bad type: {name}"
    for name in _ALERT_NULLABLE_TEXT_FIELDS:
        if record[name] is not None and not isinstance(record[name], str):
            return None, f"bad type: {name}"
    for name in _ALERT_NULLABLE_INT_FIELDS:
        value = record[name]
        # `isinstance(True, int)` is True in Python, and a boolean line number is a
        # malformed record, not line 1.
        if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
            return None, f"bad type: {name}"
    if record["severity"] not in SEVERITIES:
        return None, "bad type: severity"
    if record["tool"] not in TOOLS:
        return None, "bad type: tool"
    return (
        Alert(
            tool=record["tool"],
            severity=record["severity"],
            file_or_url=record["file_or_url"],
            title=record["title"],
            description=record["description"],
            rule_id=record["rule_id"],
            cwe=record["cwe"],
            line=record["line"],
            source_path=record["source_path"],
        ),
        "",
    )


def _run_dir(from_run: str) -> tuple[Path | None, str]:
    """`"<kind>/<name>"` -> the run directory on disk. bench runs sit directly under
    `data/results/`; sweep and ablation arms sit one level deeper, under their kind
    (the same layout `scan_runner.list_results()` walks)."""
    kind, _, name = from_run.partition("/")
    if not kind or not name:
        return None, from_run
    run_dir = RESULTS_ROOT / name if kind == "bench" else RESULTS_ROOT / kind / name
    return (run_dir if run_dir.is_dir() else None), from_run


def _load_from_run(from_run: str) -> tuple[list[Alert], str]:
    """Ingest a run through the shipped v1.1 normalizer. Read-only by construction:
    `append_alerts()` is never called, so `data/kb/alerts.jsonl` is untouched."""
    run_dir, source = _run_dir(from_run)
    if run_dir is None:
        logger.warning("no run directory resolves for %r — treating the input as empty", from_run)
        return [], source
    summary = run_dir / "bench_summary.json"
    if summary.exists():
        return normalize_bench_summary(summary), source
    sarif_files = sorted(run_dir.glob("*.sarif"))
    if sarif_files:
        alerts: list[Alert] = []
        for sarif_path in sarif_files:
            alerts.extend(normalize_sarif(sarif_path, "semgrep"))
        return alerts, source
    logger.warning("run %r carries no bench summary and no SARIF — the input is empty", from_run)
    return [], source


def load_alerts(input_path: Path = KB_ALERTS_PATH, from_run: str | None = None) -> AlertLoad:
    """Read normalized alerts. A missing or zero-byte file is `alerts=[]`, never an
    exception (FR21 scenario 1); a bad line is skipped with its 1-based line number and a
    closed-set reason while the rest of the file keeps loading (FR21 scenario 2)."""
    if from_run:
        alerts, source = _load_from_run(from_run)
        return AlertLoad(alerts=alerts, skipped=[], lines_read=len(alerts), source=source)

    path = Path(input_path)
    source = _relative(path)
    if not path.exists() or path.stat().st_size == 0:
        return AlertLoad(alerts=[], skipped=[], lines_read=0, source=source)

    alerts = []
    skipped: list[SkippedRecord] = []
    lines_read = 0
    with path.open(encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            text = raw.strip()
            if not text:
                # A blank separator is not a record, so it is neither read nor skipped —
                # counting it would put the conservation arithmetic permanently off by one.
                continue
            lines_read += 1
            try:
                record = json.loads(text)
            except json.JSONDecodeError:
                skipped.append(SkippedRecord(line_no, "invalid json", text[:RAW_LINE_LIMIT]))
                continue
            if not isinstance(record, dict):
                skipped.append(SkippedRecord(line_no, "not an object", text[:RAW_LINE_LIMIT]))
                continue
            alert, reason = _validate_alert(record)
            if alert is None:
                skipped.append(SkippedRecord(line_no, reason, text[:RAW_LINE_LIMIT]))
                continue
            alerts.append(alert)
    return AlertLoad(alerts=alerts, skipped=skipped, lines_read=lines_read, source=source)


# --- group (FR17, ADR 26) ---------------------------------------------------------


def _slugify(text: str) -> str:
    return _SLUG_RE.sub("-", text.lower()).strip("-") or "untitled"


def _rule_family(alert: Alert) -> str:
    """Last dotted segment of the rule id. The ids on disk are absolute-path-derived
    (`Users.<...>.rules.benchmarkjava.weak-prng.math-random`), so the full id would make
    the group key machine-specific and break `finding_id` stability across machines.
    Metis reports no rule id at all, so its title is slugified instead."""
    if alert.rule_id:
        return alert.rule_id.split(".")[-1]
    return _slugify(alert.title)


def _group_key(alert: Alert) -> str:
    return f"{alert.cwe or 'nocwe'}::{_rule_family(alert)}"


def _modal(values: list[str]) -> str:
    """Most frequent value, ties broken alphabetically so the result is stable."""
    counts = Counter(values)
    top = max(counts.values())
    return sorted(name for name, count in counts.items() if count == top)[0]


def _ranked_distinct(values: list[str], keep: int) -> list[str]:
    counts = Counter(value for value in values if value)
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [value for value, _ in ordered[:keep]]


def group_alerts(alerts: list[Alert]) -> list[AlertGroup]:
    """Two-stage grouping (ADR 26).

    Stage 1 collapses *exact* duplicates — same tool, file, line and rule id — which are
    re-scan noise, counting each collapse. Stage 2 groups the survivors by
    `(cwe, rule_family)`, which is the real signal: one weakness class seen in many files.
    The per-file list survives grouping rather than being averaged away.
    """
    survivors: list[Alert] = []
    duplicates: list[int] = []
    seen: dict[tuple, int] = {}
    for alert in alerts:
        key = (alert.tool, alert.file_or_url, alert.line, alert.rule_id)
        if key in seen:
            duplicates[seen[key]] += 1
            continue
        seen[key] = len(survivors)
        survivors.append(alert)
        duplicates.append(0)

    members: dict[str, list[int]] = {}
    for index, alert in enumerate(survivors):
        members.setdefault(_group_key(alert), []).append(index)

    groups: list[AlertGroup] = []
    for key, indexes in members.items():
        picked = [survivors[index] for index in indexes]
        occurrences = sorted(
            (
                AlertRef(
                    file_or_url=alert.file_or_url,
                    line=alert.line,
                    tool=alert.tool,
                    rule_id=alert.rule_id,
                )
                for alert in picked
            ),
            key=lambda ref: (ref.file_or_url, ref.line if ref.line is not None else -1, ref.tool),
        )
        groups.append(
            AlertGroup(
                group_key=key,
                cwe=picked[0].cwe,
                rule_family=_rule_family(picked[0]),
                title=_modal([alert.title for alert in picked]),
                tool_severity=max(
                    (alert.severity for alert in picked), key=lambda name: SEVERITY_RANK[name]
                ),
                tools=sorted({alert.tool for alert in picked}),
                occurrences=occurrences,
                occurrence_count=len(occurrences),
                exact_duplicates_removed=sum(duplicates[index] for index in indexes),
                descriptions=_ranked_distinct([alert.description for alert in picked], 3),
                source_paths=sorted({alert.source_path for alert in picked}),
            )
        )

    groups.sort(
        key=lambda group: (
            -SEVERITY_RANK[group.tool_severity],
            -group.occurrence_count,
            group.group_key,
        )
    )
    # The FR17 guarantee, asserted rather than described. Holds for [] as 0 == 0.
    accounted = sum(group.occurrence_count for group in groups) + sum(
        group.exact_duplicates_removed for group in groups
    )
    assert accounted == len(alerts), (
        f"grouping lost records: {accounted} accounted for out of {len(alerts)} alerts"
    )
    return groups


# --- retrieval (FR18) -------------------------------------------------------------


def attach_kb(
    group: AlertGroup, top_k: int = 3, min_score: float = 0.05
) -> list[kb_search.KBHit]:
    """One call into the shipped KB seam, in KEYWORD mode: FR19's byte-identical offline
    rerun needs retrieval that is deterministic and needs no network. An absent KB
    directory or a search failure yields `[]`, which is an expected result that floors
    confidence to `low` (ADR 27) — never an exception."""
    query = " ".join(
        part
        for part in (group.title, group.cwe or "", group.descriptions[0] if group.descriptions else "")
        if part
    )
    try:
        return kb_search.search_kb(query, mode="keyword", top_k=top_k, min_score=min_score)
    except Exception as exc:  # noqa: BLE001 - the KB is optional context, never a hard dep
        logger.warning("KB retrieval unavailable for %s (%s) — continuing with no KB hits",
                       group.group_key, exc)
        return []


# --- clamps (FR19, ADR 27) --------------------------------------------------------


def clamp_severity(model_severity: str, tool_severity: str) -> SeverityDecision:
    """The model may move severity by one rank with a written rationale; anything further
    is pulled back to exactly one rank from what the tools reported. Anchoring to the
    tool's own value keeps the report auditable against the scan output."""
    if model_severity not in SEVERITY_RANK:
        raise ValueError(f"unknown severity: {model_severity!r}")
    if tool_severity not in SEVERITY_RANK:
        raise ValueError(f"unknown severity: {tool_severity!r}")
    distance = SEVERITY_RANK[model_severity] - SEVERITY_RANK[tool_severity]
    if abs(distance) <= 1:
        return SeverityDecision(severity=model_severity, clamped=False, distance=distance)
    step = 1 if distance > 0 else -1
    # |distance| > 1 guarantees at least two ranks of room, so a single step can never
    # leave the scale — the info and critical ends are safe by arithmetic, not by luck.
    moved = _RANK_TO_SEVERITY[SEVERITY_RANK[tool_severity] + step]
    return SeverityDecision(severity=moved, clamped=True, distance=distance)


def clamp_confidence(
    model_confidence: str,
    group: AlertGroup,
    kb_hits: list[kb_search.KBHit],
    analysis_source: str,
) -> ConfidenceDecision:
    """Floors applied in order. `reason` always names the rule that decided, including
    the case where the model's own value was accepted unchanged."""
    if model_confidence not in CONFIDENCES:
        raise ValueError(f"unknown confidence: {model_confidence!r}")
    if analysis_source == "fallback":
        return ConfidenceDecision(
            "low", "fallback path: no model analysis, so confidence is floored to low"
        )
    if not kb_hits:
        return ConfidenceDecision(
            "low", "no knowledge-base document cleared the score floor, so confidence is low"
        )
    if model_confidence == "high" and not (group.occurrence_count > 1 or len(group.tools) > 1):
        return ConfidenceDecision(
            "medium",
            "high needs a knowledge-base match plus repeat occurrences or multi-tool "
            "agreement; this group has a single occurrence from one tool, so it is medium",
        )
    return ConfidenceDecision(model_confidence, "model value accepted")


# --- finding assembly (FR18, FR19) ------------------------------------------------


def _section(body: str, heading: str) -> str:
    match = re.search(
        _SECTION_RE_TEMPLATE.format(heading=re.escape(heading)),
        body,
        re.DOTALL | re.MULTILINE,
    )
    return match.group(1).strip() if match else ""


def _truncate(text: str, limit: int) -> str:
    collapsed = " ".join(text.split())
    return collapsed if len(collapsed) <= limit else collapsed[:limit].rsplit(" ", 1)[0] + " …"


def _owasp_ref(kb_hits: list[kb_search.KBHit]) -> str | None:
    """The top-scoring OWASP Top 10 document among the hits, or None. Hits arrive already
    sorted by score, so the first match is the highest-scoring one."""
    for hit in kb_hits:
        if hit.doc_id.startswith("owasp-top10/"):
            return hit.doc_id
    return None


def _locations(group: AlertGroup) -> list[Location]:
    """Straight from the group's own alerts. The model is never asked for, and never
    believed about, a path or a line number (FR18 NFR)."""
    return [
        Location(file=ref.file_or_url, line=ref.line, tool=ref.tool)
        for ref in group.occurrences
    ]


def _evidence(group: AlertGroup) -> Evidence:
    rule_ids = [ref.rule_id for ref in group.occurrences if ref.rule_id]
    return Evidence(
        tool="+".join(group.tools),
        rule_id=_modal(rule_ids) if rule_ids else None,
        raw_message=group.descriptions[0] if group.descriptions else "",
        occurrence_count=group.occurrence_count,
        files_affected=len({ref.file_or_url for ref in group.occurrences}),
        source_paths=list(group.source_paths),
    )


def _kept_kb_refs(
    claimed_ids: list[str], kb_hits: list[kb_search.KBHit]
) -> tuple[list[str], int]:
    """Intersect the ids a model claimed with the ones actually handed to it. A
    hallucinated id is dropped, and the drop is returned so meta can count it."""
    available = {hit.doc_id for hit in kb_hits}
    kept: list[str] = []
    for doc_id in claimed_ids:
        if doc_id in available and doc_id not in kept:
            kept.append(doc_id)
    return kept, len(claimed_ids) - len(kept)


def _finding_id(group_key: str) -> str:
    return hashlib.sha256(group_key.encode("utf-8")).hexdigest()[:12]


def fallback_finding(
    group: AlertGroup,
    kb_hits: list[kb_search.KBHit],
    reason: str,
    prompt=None,
) -> Finding:
    """The deterministic finding (ADR 29). Used for offline runs and for every model
    failure. It is a complete, readable record — but it says in its first sentence that
    no model analysed it and why, so it can never be mistaken for one that was."""
    top = kb_hits[0] if kb_hits else None
    tool_message = group.descriptions[0] if group.descriptions else "(công cụ không kèm mô tả)"

    preamble = (
        f"Không có phân tích từ mô hình cho nhóm cảnh báo này — {reason}. "
        "Nội dung dưới đây được ghép tự động từ tài liệu trong kho tri thức và từ thông "
        "điệp gốc của công cụ quét, không phải do mô hình viết."
    )
    if top is not None:
        kb_part = f"Tài liệu tham chiếu «{top.title}» ({top.doc_id}): {_truncate(top.body, FALLBACK_KB_EXCERPT_CHARS)}"
    else:
        kb_part = (
            "Không có tài liệu nào trong kho tri thức đạt ngưỡng tương đồng cho nhóm này, "
            "nên phần giải thích chỉ dựa trên thông điệp của công cụ quét."
        )
    explanation = (
        f"{preamble}\n\n{kb_part}\n\nThông điệp từ công cụ quét: {tool_message}"
    )

    files = len({ref.file_or_url for ref in group.occurrences})
    how_to_verify = (
        f"Mở {group.occurrence_count} vị trí được liệt kê trong trường `locations` "
        f"({files} tệp) và đối chiếu thủ công với thông điệp gốc của công cụ quét."
    )
    if top is not None:
        how_to_verify += f" Mẫu mã dễ bị tấn công nằm trong tài liệu {top.doc_id}."

    fixed_section = _section(top.body, "Fixed") if top is not None else ""
    if fixed_section:
        how_to_fix = (
            f"Theo tài liệu {top.doc_id}, cách khắc phục được khuyến nghị là:\n\n{fixed_section}"
        )
    elif top is not None:
        how_to_fix = (
            f"Chưa có bản vá mẫu trong kho tri thức cho nhóm này; hãy đọc tài liệu "
            f"{top.doc_id} và áp dụng theo hướng dẫn ở đó."
        )
    else:
        how_to_fix = (
            "Chưa có tài liệu tham chiếu cho nhóm này — cần một người rà soát thủ công "
            "trước khi kết luận cách khắc phục."
        )

    confidence = clamp_confidence("low", group, kb_hits, "fallback")
    return Finding(
        finding_id=_finding_id(group.group_key),
        title=group.title,
        severity=group.tool_severity,
        severity_source=group.tool_severity,
        severity_rationale=(
            "Không có đề xuất từ mô hình, nên giữ nguyên mức độ cao nhất mà công cụ quét báo."
        ),
        severity_clamped=False,
        cwe=group.cwe,
        owasp=_owasp_ref(kb_hits),
        locations=_locations(group),
        evidence=_evidence(group),
        explanation=explanation,
        remediation=Remediation(
            how_to_verify=how_to_verify,
            how_to_fix=how_to_fix,
            code_hint=top.vulnerable_code if top is not None else None,
        ),
        confidence=confidence.confidence,
        confidence_reason=confidence.reason,
        kb_refs=[hit.doc_id for hit in kb_hits],
        analysis_source="fallback",
        model=None,
        prompt_sha256=getattr(prompt, "sha256", "") or "",
    )


def build_finding(
    group: AlertGroup,
    kb_hits: list[kb_search.KBHit],
    analysis,
    prompt=None,
) -> Finding:
    """Assemble the record. Prose comes from the model; `locations`, `evidence`, `cwe` and
    every path and line number come from the group's own alerts and never from the model
    (FR18 NFR). A missing or failed analysis routes to `fallback_finding()` rather than
    dropping the group — losing a group silently is the failure this project already
    lived through."""
    if analysis is None or not getattr(analysis, "ok", False):
        reason = getattr(analysis, "failure_reason", None) or "mô hình không trả về phân tích"
        return fallback_finding(group, kb_hits, reason, prompt)

    model_finding = analysis.finding
    severity = clamp_severity(model_finding.severity, group.tool_severity)
    confidence = clamp_confidence(model_finding.confidence, group, kb_hits, "llm")
    kb_refs, _dropped = _kept_kb_refs(list(model_finding.kb_doc_ids), kb_hits)
    return Finding(
        finding_id=_finding_id(group.group_key),
        title=model_finding.title_vi,
        severity=severity.severity,
        severity_source=group.tool_severity,
        severity_rationale=model_finding.severity_rationale_vi,
        severity_clamped=severity.clamped,
        cwe=group.cwe,
        owasp=_owasp_ref(kb_hits),
        locations=_locations(group),
        evidence=_evidence(group),
        explanation=model_finding.explanation_vi,
        remediation=Remediation(
            how_to_verify=model_finding.how_to_verify_vi,
            how_to_fix=model_finding.how_to_fix_vi,
            code_hint=model_finding.code_hint,
        ),
        confidence=confidence.confidence,
        confidence_reason=confidence.reason,
        kb_refs=kb_refs,
        analysis_source="llm",
        model=getattr(analysis, "model", None),
        prompt_sha256=getattr(prompt, "sha256", "") or "",
    )


# --- the prompt (ADR 28) ----------------------------------------------------------


def load_system_prompt(path: Path = PROMPT_PATH) -> SystemPrompt:
    """Read the versioned prompt file and hash it. Hashing it into every report means an
    output change always has an explanation. There is no implicit built-in prompt to fall
    back to — an absent or empty file is an error, not a default."""
    path = Path(path)
    if not path.exists():
        raise PromptMissingError(f"no prompt file at {path} — the agent will not run without one")
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        raise PromptMissingError(f"prompt file {path} is empty — the agent will not run on it")
    version = "unversioned"
    match = _PROMPT_FRONTMATTER_RE.match(text)
    if match:
        for line in match.group(1).splitlines():
            key, separator, value = line.partition(":")
            if separator and key.strip() == "version" and value.strip():
                version = value.strip()
                break
    return SystemPrompt(
        text=text,
        path=_relative(path),
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        version=version,
    )


# --- the one bounded call (ADR 24, 25, 30) ----------------------------------------


def _user_turn(group: AlertGroup, kb_hits: list[kb_search.KBHit]) -> str:
    """Everything the model is given, and nothing else. Deliberately excludes file paths
    and line numbers: it has no use for them, and not supplying them is the cheapest way
    to stop it echoing them back as if they were its own finding."""
    lines = [
        "## Nhóm cảnh báo cần phân tích",
        "",
        f"- Tên do công cụ đặt: {group.title}",
        f"- CWE: {group.cwe or 'không xác định'}",
        f"- Mức độ công cụ báo (tool severity): {group.tool_severity}",
        f"- Số lần xuất hiện: {group.occurrence_count} (trên "
        f"{len({ref.file_or_url for ref in group.occurrences})} tệp)",
        f"- Công cụ phát hiện: {', '.join(group.tools)}",
        "",
        "### Thông điệp gốc từ công cụ quét",
        "",
    ]
    lines += [f"{index}. {message}" for index, message in enumerate(group.descriptions, start=1)]
    lines += ["", "### Trích đoạn tài liệu từ kho tri thức", ""]
    if kb_hits:
        for hit in kb_hits:
            lines += [
                f"#### doc_id: {hit.doc_id}  (tiêu đề: {hit.title})",
                "",
                _truncate(hit.body, 1500),
                "",
            ]
        lines.append(
            "Các doc_id hợp lệ cho trường kb_doc_ids: "
            + ", ".join(hit.doc_id for hit in kb_hits)
        )
    else:
        lines.append(
            "Không có tài liệu nào khớp. Trường kb_doc_ids phải là mảng rỗng, và hãy hạ "
            "confidence tương ứng."
        )
    lines += ["", "Trả về đúng một đối tượng JSON theo lược đồ đã mô tả, không có gì khác."]
    return "\n".join(lines)


def _post_chat(messages: list[dict], model: str, timeout: int) -> tuple[str | None, int, str | None]:
    """One POST. Returns `(content, total_tokens, failure_reason)` — never raises for a
    model or transport problem, because the caller is the one that decides what a failure
    means for the report."""
    base_url = os.environ.get("OPENCODE_BASE_URL", "").rstrip("/")
    api_key = os.environ.get("OPENCODE_API_KEY", "")
    try:
        response = requests.post(
            f"{base_url}{CHAT_ROUTE}",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": model, "messages": messages, "temperature": 0},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        logger.warning("analysis call failed in transport: %s", exc)
        return None, 0, "transport_error"

    if response.status_code >= 400:
        logger.warning("analysis call returned status %s", response.status_code)
        return None, 0, "http_error"

    try:
        payload = response.json()
    except ValueError:
        return None, 0, "non_json"

    usage = payload.get("usage") or {}
    try:
        total_tokens = int(usage.get("total_tokens") or 0)
    except (TypeError, ValueError):
        total_tokens = 0

    # ADR 30 — the week-2 incident, closed. A 2xx that reports no work done is not a
    # success; a status code is a claim, token usage is evidence. A reply carrying no
    # usage block at all reports no evidence either, so it lands here too.
    if total_tokens == 0:
        logger.warning("analysis call returned 2xx but reported zero tokens — treating as failure")
        return None, 0, "zero_tokens"

    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return None, total_tokens, "empty_response"
    if not isinstance(content, str) or not content.strip():
        return None, total_tokens, "empty_response"
    return content, total_tokens, None


def _validate_model_finding(
    content: str, kb_hits: list[kb_search.KBHit]
) -> tuple[ModelFinding | None, str, str]:
    """Closed-schema validation. Returns `(finding, reason, detail)`; `detail` is fed back
    verbatim into the single retry so the model is told exactly what it got wrong."""
    text = content.strip()
    fence = _FENCE_RE.match(text)
    if fence:
        # The prompt forbids a markdown fence, but unwrapping one costs nothing and saves
        # a paid retry. This is transport unwrapping, not schema leniency — everything
        # below stays strict.
        text = fence.group(1)
    try:
        record = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, "non_json", f"câu trả lời không phải JSON hợp lệ ({exc.msg})"
    if not isinstance(record, dict):
        return None, "schema_invalid", "câu trả lời phải là một đối tượng JSON"

    keys = set(record)
    extra = sorted(keys - _MODEL_FINDING_KEYS)
    if extra:
        return None, "schema_invalid", f"có khóa thừa không được phép: {', '.join(extra)}"
    missing = sorted(_MODEL_FINDING_KEYS - keys)
    if missing:
        return None, "schema_invalid", f"thiếu khóa: {', '.join(missing)}"

    for key in _MODEL_FINDING_TEXT_KEYS:
        value = record[key]
        if not isinstance(value, str) or not value.strip():
            return None, "schema_invalid", f"khóa {key} phải là chuỗi khác rỗng"
    if len(record["title_vi"]) > TITLE_MAX_CHARS:
        return None, "schema_invalid", f"title_vi dài quá {TITLE_MAX_CHARS} ký tự"

    code_hint = record["code_hint"]
    if code_hint is not None and (not isinstance(code_hint, str) or not code_hint.strip()):
        return None, "schema_invalid", "code_hint phải là chuỗi khác rỗng hoặc null"
    if record["severity"] not in SEVERITY_RANK:
        return None, "schema_invalid", f"severity không hợp lệ: {record['severity']!r}"
    if record["confidence"] not in CONFIDENCES:
        return None, "schema_invalid", f"confidence không hợp lệ: {record['confidence']!r}"
    doc_ids = record["kb_doc_ids"]
    if not isinstance(doc_ids, list) or any(not isinstance(item, str) for item in doc_ids):
        return None, "schema_invalid", "kb_doc_ids phải là mảng chuỗi"

    return (
        ModelFinding(
            title_vi=record["title_vi"],
            explanation_vi=record["explanation_vi"],
            how_to_verify_vi=record["how_to_verify_vi"],
            how_to_fix_vi=record["how_to_fix_vi"],
            code_hint=code_hint,
            severity=record["severity"],
            severity_rationale_vi=record["severity_rationale_vi"],
            confidence=record["confidence"],
            kb_doc_ids=list(doc_ids),
        ),
        "",
        "",
    )


def analyze_group(
    group: AlertGroup,
    kb_hits: list[kb_search.KBHit],
    prompt: SystemPrompt,
    model: str | None = None,
    timeout: int = CALL_TIMEOUT_SECONDS,
    allow_retry: bool = True,
) -> GroupAnalysis:
    """Exactly one paid call per group, plus at most one retry whose message names the
    validation error (ADR 24). A transport, status or zero-token failure is NOT retried —
    retrying those buys nothing and costs money. Never raises."""
    resolved_model = model or os.environ.get("CUSTOM_SCAN_MODEL") or ""
    messages = [
        {"role": "system", "content": prompt.text},
        {"role": "user", "content": _user_turn(group, kb_hits)},
    ]
    total_tokens = 0
    calls = 0
    attempts = 2 if allow_retry else 1

    for attempt in range(1, attempts + 1):
        content, tokens, reason = _post_chat(messages, resolved_model, timeout)
        calls += 1
        total_tokens += tokens
        if reason is not None:
            return GroupAnalysis(
                ok=False,
                failure_reason=reason,
                failure_detail=reason,
                model=resolved_model,
                total_tokens=total_tokens,
                calls=calls,
            )

        finding, validation_reason, detail = _validate_model_finding(content, kb_hits)
        if finding is not None:
            kept, dropped = _kept_kb_refs(finding.kb_doc_ids, kb_hits)
            finding.kb_doc_ids = kept
            return GroupAnalysis(
                ok=True,
                finding=finding,
                model=resolved_model,
                total_tokens=total_tokens,
                calls=calls,
                dropped_kb_ids=dropped,
            )

        if attempt == attempts:
            return GroupAnalysis(
                ok=False,
                # A validation failure that had no retry left keeps its own reason; one
                # that burned the retry and failed again is `retry_exhausted`.
                failure_reason="retry_exhausted" if allow_retry else validation_reason,
                failure_detail=detail,
                model=resolved_model,
                total_tokens=total_tokens,
                calls=calls,
            )

        logger.warning("model reply rejected for %s (%s) — retrying once", group.group_key, detail)
        messages = messages + [
            {"role": "assistant", "content": content},
            {
                "role": "user",
                "content": (
                    f"Câu trả lời trên không hợp lệ: {detail}. "
                    "Hãy trả lời lại bằng đúng một đối tượng JSON theo lược đồ đã mô tả, "
                    "không kèm bất kỳ ký tự nào khác và không rào markdown."
                ),
            },
        ]

    # Unreachable: every branch above returns.
    return GroupAnalysis(ok=False, failure_reason="retry_exhausted", model=resolved_model)


def estimate_analysis_cost(
    groups: list[AlertGroup], limit: int | None = None, model: str | None = None
) -> AnalysisEstimate:
    """Same guard shape as `scan_runner.estimate_cost()` (FR5): the caller can always say
    how many paid calls a run will make before making any of them."""
    resolved_model = model or os.environ.get("CUSTOM_SCAN_MODEL") or "(chưa đặt mô hình)"
    call_count = len(groups) if limit is None else max(0, min(len(groups), limit))
    warning_text = ""
    if call_count > 0:
        warning_text = (
            f"Lần chạy này sẽ gọi mô hình trả phí {call_count} lần "
            f"(mỗi nhóm cảnh báo một lần, mô hình {resolved_model})"
            + (
                f", bỏ qua {len(groups) - call_count} nhóm còn lại vì --limit."
                if call_count < len(groups)
                else f", trên tổng số {len(groups)} nhóm."
            )
        )
    return AnalysisEstimate(
        group_count=len(groups),
        call_count=call_count,
        model=resolved_model,
        warning_text=warning_text,
    )


# --- orchestration (FR20, FR21) ---------------------------------------------------


def analyze(
    input_path: Path = KB_ALERTS_PATH,
    from_run: str | None = None,
    top_k: int = 3,
    min_score: float = 0.05,
    limit: int | None = None,
    no_llm: bool = False,
    model: str | None = None,
    progress: Callable[[int, int, str], None] | None = None,
) -> AnalysisReport:
    """Run the pipeline and return the report. Never raises for empty or invalid input —
    those are statuses (FR21), not exceptions. A missing prompt file IS an exception, and
    only on the model path: the agent never runs on an implicit prompt (ADR 28). Writing
    is `write_report()`'s job alone.
    """
    started = time.monotonic()
    # Read the module global at call time, not at def time, so a caller (or a test) can
    # point the run at a different prompt file.
    prompt = None if no_llm else load_system_prompt(PROMPT_PATH)
    resolved_model = None if no_llm else (model or os.environ.get("CUSTOM_SCAN_MODEL") or "")

    load = load_alerts(input_path=input_path, from_run=from_run)
    groups = group_alerts(load.alerts)

    if load.lines_read == 0 or (not load.alerts and not load.skipped):
        status: str = "empty"
    elif not load.alerts:
        status = "invalid_input"
    else:
        status = "ok"

    # `limit` selects which groups reach the model. Groups are already ranked
    # severity-first, so the head is the highest-severity N; the tail still becomes
    # findings, which is what keeps the conservation arithmetic true under --limit.
    head = groups if limit is None else groups[:limit]
    tail = [] if limit is None else groups[limit:]

    findings: list[Finding] = []
    llm_calls = 0
    llm_failures = 0
    failure_reasons: Counter = Counter()
    dropped_kb_ids = 0
    total_tokens = 0

    for position, group in enumerate(head + tail, start=1):
        if progress is not None:
            progress(position, len(groups), group.group_key)
        kb_hits = attach_kb(group, top_k=top_k, min_score=min_score)

        if no_llm:
            findings.append(fallback_finding(group, kb_hits, NO_LLM_REASON, None))
            continue
        if position > len(head):
            findings.append(fallback_finding(group, kb_hits, LIMIT_REASON, None))
            continue

        analysis = analyze_group(group, kb_hits, prompt, model=resolved_model)
        llm_calls += analysis.calls
        total_tokens += analysis.total_tokens
        if analysis.ok:
            dropped_kb_ids += analysis.dropped_kb_ids
        else:
            llm_failures += 1
            failure_reasons[analysis.failure_reason] += 1
        findings.append(build_finding(group, kb_hits, analysis, prompt))

    # A partial degradation is honest and still useful; a TOTAL one is a broken run
    # pretending to be a report, so it must be impossible to mistake for success from the
    # status (and therefore the exit code) alone — ADR 29.
    if not no_llm and head and llm_failures == len(head):
        status = "degraded"

    duplicates_removed = sum(group.exact_duplicates_removed for group in groups)
    occurrences = sum(group.occurrence_count for group in groups)
    meta = AnalysisMeta(
        status=status,
        generated_at=datetime.now(timezone.utc).isoformat(),
        input_source=load.source,
        alerts_read=load.lines_read,
        alerts_valid=len(load.alerts),
        alerts_skipped=len(load.skipped),
        skipped=load.skipped,
        exact_duplicates_removed=duplicates_removed,
        groups=len(groups),
        findings=len(findings),
        accounted_for=(occurrences + duplicates_removed + len(load.skipped) == load.lines_read),
        limit_applied=limit,
        llm_calls=llm_calls,
        llm_failures=llm_failures,
        llm_failure_reasons=dict(sorted(failure_reasons.items())),
        dropped_kb_ids=dropped_kb_ids,
        total_tokens=None if no_llm else total_tokens,
        model=resolved_model,
        prompt_path=prompt.path if prompt else "",
        prompt_sha256=prompt.sha256 if prompt else "",
        prompt_version=prompt.version if prompt else "unversioned",
        duration_seconds=round(time.monotonic() - started, 3),
    )
    return AnalysisReport(findings=findings, meta=meta)


# --- serialization (FR20, ADR 31) -------------------------------------------------


def write_report(report: AnalysisReport, out_dir: Path = ANALYSIS_DIR) -> WriteResult:
    """The only side effect in this module. `report.jsonl` is pure JSONL — one finding per
    line, no header record — so `wc -l` equals the finding count and any consumer can
    `json.loads` every line. Every run-scoped value goes to the sidecar instead, which is
    what makes two identical offline runs byte-identical."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = out_dir / REPORT_FILENAME
    meta_path = out_dir / META_FILENAME
    jsonl_path.write_text(
        "".join(
            json.dumps(asdict(finding), ensure_ascii=False, sort_keys=True) + "\n"
            for finding in report.findings
        ),
        encoding="utf-8",
    )
    meta_path.write_text(
        json.dumps(asdict(report.meta), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return WriteResult(
        jsonl_path=str(jsonl_path),
        meta_path=str(meta_path),
        findings_written=len(report.findings),
    )


def _finding_from_dict(record: dict) -> Finding:
    return Finding(
        **{
            **record,
            "locations": [Location(**item) for item in record["locations"]],
            "evidence": Evidence(**record["evidence"]),
            "remediation": Remediation(**record["remediation"]),
        }
    )


def load_report(out_dir: Path = ANALYSIS_DIR) -> AnalysisReport | None:
    """Read a report back. `None` when none exists yet — the UI renders a "not generated"
    state naming the command, never an error (FR22). A findings line that will not parse
    raises rather than yielding a quietly partial report."""
    out_dir = Path(out_dir)
    jsonl_path = out_dir / REPORT_FILENAME
    meta_path = out_dir / META_FILENAME
    if not jsonl_path.exists() or not meta_path.exists():
        return None

    findings: list[Finding] = []
    for line_no, raw in enumerate(jsonl_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            findings.append(_finding_from_dict(json.loads(raw)))
        except (json.JSONDecodeError, TypeError, KeyError) as exc:
            raise ReportCorruptError(
                f"{jsonl_path} line {line_no} is not a readable finding: {exc}"
            ) from exc

    try:
        meta_record = json.loads(meta_path.read_text(encoding="utf-8"))
        meta = AnalysisMeta(
            **{
                **meta_record,
                "skipped": [SkippedRecord(**item) for item in meta_record["skipped"]],
            }
        )
    except (json.JSONDecodeError, TypeError, KeyError) as exc:
        raise ReportCorruptError(f"{meta_path} is not a readable sidecar: {exc}") from exc

    return AnalysisReport(findings=findings, meta=meta)
