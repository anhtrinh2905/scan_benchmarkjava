"""Deterministic query layer over a generated analysis report (v1.8 increment).

Library-style seam, the same shape as `alert_normalizer.py` / `kb_search.py` /
`security_agent.py`: flat imports, no Streamlit, no CLI flag parsing, no process
termination, no network. Everything here is a pure function of an already-loaded
`AnalysisReport`.

This module exists to answer the question the Security Report page could not: *"how many
critical findings are there, and which files carry them?"* — without a model being the one
who counts. The chat layer (`report_chat.py`) may use a model to pick **which** query to
run and to narrate the result in prose, but the numbers themselves are always computed
here, in Python, from the report on disk (ADR 24's rule, extended to Q&A).

Three properties the rest of the stack leans on:

* **Closed operation set.** `OPS` and `DIMENSIONS` are enumerated. A router — keyword or
  model — cannot ask for an operation that does not exist; `validate_spec()` rejects it
  and names why. There is no eval, no attribute lookup by string, no passthrough.
* **Conservation.** For every `count_by` result, `sum(row["count"]) == result.total`, and
  `total` is the number of findings that survived the filters. A dimension whose value is
  missing on a finding counts under `UNKNOWN_LABEL` rather than vanishing.
* **Provenance.** Every `QueryResult` carries `finding_ids` — exactly which findings the
  answer rests on — so a claim on screen can be traced back to lines of `report.jsonl`.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Literal

# Type-only: this module never constructs a report, it is always handed one.
from security_agent import AnalysisReport, Finding

Op = Literal[
    "overview",
    "count_by",
    "matrix",
    "top_files",
    "list_findings",
    "lookup",
    "kb_coverage",
]

OPS: tuple[str, ...] = (
    "overview",
    "count_by",
    "matrix",
    "top_files",
    "list_findings",
    "lookup",
    "kb_coverage",
)

# The dimensions a finding can be counted along. Each maps to a reader below rather than
# to `getattr(finding, name)` — a closed set stays closed even when the router is a model.
DIMENSIONS: tuple[str, ...] = (
    "severity",
    "confidence",
    "cwe",
    "owasp",
    "tool",
    "analysis_source",
)

# The filter keys `apply_filters` understands. Anything else is a spec error, not a
# silently-ignored key — a filter that does nothing is worse than one that is refused,
# because the count still looks authoritative.
FILTER_KEYS: tuple[str, ...] = (
    "severity",
    "confidence",
    "cwe",
    "owasp",
    "tool",
    "analysis_source",
    "file",
    "text",
)

# Ordered scales, declared once in DESIGN.md and mirrored here so a chart and a table sort
# the same way. Ordinal dimensions keep their scale order; nominal ones sort by count.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
CONFIDENCE_ORDER = ("high", "medium", "low")
ORDERED_DIMENSIONS = {
    "severity": SEVERITY_ORDER,
    "confidence": CONFIDENCE_ORDER,
}

# The `matrix` op cross-tabulates exactly these two, and the axes are fixed rather than
# taken from the spec. Both are decided by Python (severity is clamped to within ±1 of what
# the tool reported; confidence is floored when the evidence is thin), so the grid answers
# "what did the pipeline conclude, and how sure is it" — the pair a reader triages on.
# Fixing them also keeps the op set genuinely closed: no router, keyword or model, can ask
# for `cwe × file` and get a 25×80 grid nobody can read.
MATRIX_ROW = "severity"
MATRIX_COLUMN = "confidence"

# A finding with no CWE mapped, or no OWASP category matched, is a real and reportable
# state — 24 of the 93 findings in the shipped report have no OWASP category. It gets a
# label rather than being dropped, so the bar chart shows the gap instead of hiding it.
UNKNOWN_LABEL = "không xác định"

DEFAULT_LIMIT = 10
MAX_LIMIT = 100

_CWE_RE = re.compile(r"\bcwe[-\s]?(\d+)\b", re.IGNORECASE)
_FINDING_ID_RE = re.compile(r"\b([0-9a-f]{12})\b")


class QuerySpecError(ValueError):
    """A spec that cannot be run, carrying the reason in its message. Raised by
    `validate_spec()` so a bad model-produced route is a caught, labelled fallback rather
    than a traceback on the page."""


# --- shapes -----------------------------------------------------------------------


@dataclass
class QuerySpec:
    """What to ask the report. Produced either by `route_keywords()` (deterministic) or by
    a model, and validated identically in both cases."""

    op: str
    dimension: str | None = None
    filters: dict[str, str] = field(default_factory=dict)
    limit: int = DEFAULT_LIMIT


@dataclass
class QueryResult:
    """What the report answered. `table` is the whole numeric payload — the chart layer
    draws it, the chat layer narrates it, and neither recomputes it."""

    op: str
    dimension: str | None
    filters: dict[str, str]
    # Row dicts, homogeneous within a result. `count_by`/`top_files` rows are
    # {"label": str, "count": int}; `list_findings`/`lookup` rows are finding summaries;
    # `overview`/`kb_coverage` rows are {"label": str, "value": ...}.
    table: list[dict[str, Any]]
    # Exactly the findings this answer rests on, in report order.
    finding_ids: list[str]
    # The denominator: how many findings survived the filters.
    total: int
    # Human-readable one-liner naming what was asked, in Vietnamese. Rendered above the
    # table so a result is self-describing even detached from its question.
    caption: str
    note: str | None = None
    # Only `matrix` sets this: the cross-tab's column labels, in display order. Carried
    # explicitly so a renderer reads the axis from the query layer instead of reconstructing
    # it from row keys — the same reason `table` is the whole numeric payload.
    columns: list[str] = field(default_factory=list)


# --- readers ----------------------------------------------------------------------


def _dimension_value(finding: Finding, dimension: str) -> str:
    """One finding's value along one dimension, always a non-empty string."""
    if dimension == "severity":
        return finding.severity
    if dimension == "confidence":
        return finding.confidence
    if dimension == "cwe":
        return finding.cwe or UNKNOWN_LABEL
    if dimension == "owasp":
        return finding.owasp or UNKNOWN_LABEL
    if dimension == "tool":
        return finding.evidence.tool
    if dimension == "analysis_source":
        return finding.analysis_source
    raise QuerySpecError(f"chiều thống kê không hợp lệ: {dimension!r}")


def _haystack(finding: Finding) -> str:
    """Everything a free-text filter may match on. Deliberately includes the explanation:
    a question like "lỗi nào liên quan mật khẩu" should reach prose, not just titles."""
    return " ".join(
        [
            finding.title,
            finding.cwe or "",
            finding.owasp or "",
            finding.explanation,
            finding.finding_id,
        ]
        + [location.file for location in finding.locations]
    ).lower()


def _files_of(finding: Finding) -> list[str]:
    """Distinct files a finding touches, order-stable."""
    seen: list[str] = []
    for location in finding.locations:
        if location.file not in seen:
            seen.append(location.file)
    return seen


# --- validation -------------------------------------------------------------------


def validate_spec(spec: QuerySpec) -> QuerySpec:
    """Normalise and check a spec, or raise `QuerySpecError` naming the problem. Runs on
    every spec regardless of origin — a hand-written route gets the same scrutiny as a
    model-written one, which is what makes the two interchangeable."""
    if spec.op not in OPS:
        raise QuerySpecError(f"thao tác không hợp lệ: {spec.op!r} (hợp lệ: {', '.join(OPS)})")

    dimension = spec.dimension
    if spec.op == "count_by":
        if not dimension:
            raise QuerySpecError("count_by cần một chiều thống kê (dimension)")
        if dimension not in DIMENSIONS:
            raise QuerySpecError(
                f"chiều thống kê không hợp lệ: {dimension!r} (hợp lệ: {', '.join(DIMENSIONS)})"
            )
    else:
        dimension = None

    filters: dict[str, str] = {}
    for key, value in (spec.filters or {}).items():
        if key not in FILTER_KEYS:
            raise QuerySpecError(
                f"bộ lọc không hợp lệ: {key!r} (hợp lệ: {', '.join(FILTER_KEYS)})"
            )
        if value is None:
            continue
        text = str(value).strip()
        if text:
            filters[key] = text

    limit = spec.limit if isinstance(spec.limit, int) else DEFAULT_LIMIT
    limit = max(1, min(limit, MAX_LIMIT))

    return QuerySpec(op=spec.op, dimension=dimension, filters=filters, limit=limit)


def spec_from_dict(payload: Any) -> QuerySpec:
    """Build a spec from a decoded JSON object — the shape a model route returns. Every
    failure path here is a `QuerySpecError`, so the caller has exactly one thing to catch."""
    if not isinstance(payload, dict):
        raise QuerySpecError("định tuyến phải là một đối tượng JSON")
    unknown = set(payload) - {"op", "dimension", "filters", "limit"}
    if unknown:
        raise QuerySpecError(f"khoá thừa trong định tuyến: {', '.join(sorted(unknown))}")

    raw_filters = payload.get("filters") or {}
    if not isinstance(raw_filters, dict):
        raise QuerySpecError("trường filters phải là một đối tượng")

    raw_limit = payload.get("limit", DEFAULT_LIMIT)
    try:
        limit = int(raw_limit) if raw_limit is not None else DEFAULT_LIMIT
    except (TypeError, ValueError):
        raise QuerySpecError(f"limit không phải số nguyên: {raw_limit!r}") from None

    dimension = payload.get("dimension")
    return validate_spec(
        QuerySpec(
            op=str(payload.get("op") or ""),
            dimension=str(dimension) if dimension else None,
            filters={str(k): v for k, v in raw_filters.items()},
            limit=limit,
        )
    )


# --- filtering --------------------------------------------------------------------


def apply_filters(findings: list[Finding], filters: dict[str, str]) -> list[Finding]:
    """Pure. Every filter is a case-insensitive containment or equality test; unknown keys
    never arrive here because `validate_spec` refused them upstream."""
    kept = list(findings)
    for key, raw in filters.items():
        needle = raw.strip().lower()
        if not needle:
            continue
        if key in DIMENSIONS:
            kept = [f for f in kept if _dimension_value(f, key).lower() == needle]
            # `cwe` and `owasp` are written many ways in a question ("cwe 89", "A03").
            # An exact match that finds nothing falls back to containment rather than
            # reporting a confident zero.
            if not kept and key in ("cwe", "owasp"):
                kept = [
                    f
                    for f in findings
                    if needle in _dimension_value(f, key).lower()
                    and all(
                        other == key or _dimension_value(f, other).lower() == v.strip().lower()
                        for other, v in filters.items()
                        if other in DIMENSIONS
                    )
                ]
        elif key == "file":
            kept = [f for f in kept if any(needle in path.lower() for path in _files_of(f))]
        elif key == "text":
            kept = [f for f in kept if needle in _haystack(f)]
    return kept


# --- operations -------------------------------------------------------------------


def _summary_row(finding: Finding) -> dict[str, Any]:
    files = _files_of(finding)
    return {
        "finding_id": finding.finding_id,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "cwe": finding.cwe or UNKNOWN_LABEL,
        "owasp": finding.owasp or UNKNOWN_LABEL,
        "occurrences": finding.evidence.occurrence_count,
        "files": len(files),
        "first_file": files[0] if files else "",
        "analysis_source": finding.analysis_source,
    }


def _sorted_counts(counter: Counter, dimension: str) -> list[dict[str, Any]]:
    """Ordinal dimensions keep their declared scale order (and show zero rows, because an
    absent severity level is information). Nominal ones sort by count desc, label asc."""
    scale = ORDERED_DIMENSIONS.get(dimension)
    if scale:
        return [{"label": level, "count": counter.get(level, 0)} for level in scale]
    return [
        {"label": label, "count": count}
        for label, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    ]


def count_by(findings: list[Finding], dimension: str, filters: dict[str, str]) -> QueryResult:
    counter = Counter(_dimension_value(f, dimension) for f in findings)
    table = _sorted_counts(counter, dimension)
    # The conservation guarantee this module advertises. Violating it would mean a finding
    # was counted twice or dropped, and a chart would then lie about a total shown beside it.
    assert sum(row["count"] for row in table) == len(findings), "count_by lost a finding"
    return QueryResult(
        op="count_by",
        dimension=dimension,
        filters=filters,
        table=table,
        finding_ids=[f.finding_id for f in findings],
        total=len(findings),
        caption=f"Số phát hiện theo `{dimension}`" + _filter_suffix(filters),
    )


def _scale_then_extras(values: set[str], scale: tuple[str, ...]) -> list[str]:
    """The declared scale first (including levels nobody hit — an absent severity is
    information), then any value the scale does not know about, sorted. A level outside the
    scale is a pipeline bug worth seeing on screen, not a row to drop."""
    return list(scale) + sorted(values - set(scale))


def matrix(findings: list[Finding], filters: dict[str, str]) -> QueryResult:
    """Severity × confidence as one grid: how bad, against how sure.

    `count_by severity` and `count_by confidence` each answer half of this and neither can
    be crossed with the other after the fact — "how many high-severity findings are also
    low-confidence" is a different number from anything in either bar chart. That cell is
    the one triage actually needs, because it is the pile that looks urgent and may not be.

    Rows are homogeneous `{"label": <severity>, <confidence>: int, …, "count": <row total>}`,
    so the same generic renderer that draws every other table draws this one, and
    `_allowed_numbers` in the chat layer picks the cells up without a special case."""
    counter = Counter((f.severity, f.confidence) for f in findings)
    rows_axis = _scale_then_extras({f.severity for f in findings}, SEVERITY_ORDER)
    cols_axis = _scale_then_extras({f.confidence for f in findings}, CONFIDENCE_ORDER)

    table: list[dict[str, Any]] = []
    for level in rows_axis:
        row: dict[str, Any] = {"label": level}
        for column in cols_axis:
            row[column] = counter.get((level, column), 0)
        row["count"] = sum(row[column] for column in cols_axis)
        table.append(row)

    # Same conservation guarantee `count_by` makes, in two dimensions: every finding lands
    # in exactly one cell. Violating it would mean the grid disagrees with the KPI printed
    # directly above it on the page.
    assert sum(row["count"] for row in table) == len(findings), "matrix lost a finding"

    column_totals = {
        column: sum(row[column] for row in table) for column in cols_axis
    }
    # The row totals are a column of the table; the column totals are not, so they are
    # stated here rather than left for a reader to add up (and for `app.py` to compute,
    # which it is not allowed to do).
    note = "Tổng theo cột — " + " · ".join(
        f"tin cậy `{column}`: {total}" for column, total in column_totals.items()
    ) if findings else None

    return QueryResult(
        op="matrix",
        dimension=None,
        filters=filters,
        table=table,
        finding_ids=[f.finding_id for f in findings],
        total=len(findings),
        caption=f"Ma trận `{MATRIX_ROW}` × `{MATRIX_COLUMN}`" + _filter_suffix(filters),
        note=note,
        columns=cols_axis,
    )


def top_files(findings: list[Finding], filters: dict[str, str], limit: int) -> QueryResult:
    """Ranked by how many distinct findings touch the file — not by occurrence count, which
    would let one noisy rule outrank a file carrying five different vulnerabilities."""
    counter: Counter = Counter()
    for finding in findings:
        for path in _files_of(finding):
            counter[path] += 1
    rows = [
        {"label": path, "count": count}
        for path, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    ][:limit]
    return QueryResult(
        op="top_files",
        dimension=None,
        filters=filters,
        table=rows,
        finding_ids=[f.finding_id for f in findings],
        total=len(findings),
        caption=f"{len(rows)} tệp bị nhiều phát hiện nhất" + _filter_suffix(filters),
        note=(
            f"Xếp theo số phát hiện khác nhau chạm vào tệp; tổng cộng {len(counter)} tệp "
            "có ít nhất một phát hiện."
        ),
    )


def list_findings(findings: list[Finding], filters: dict[str, str], limit: int) -> QueryResult:
    """Severity-first ordering, then occurrence count — the order someone triaging would
    want, not report order."""
    ranked = sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else len(SEVERITY_ORDER),
            -f.evidence.occurrence_count,
            f.finding_id,
        ),
    )
    shown = ranked[:limit]
    return QueryResult(
        op="list_findings",
        dimension=None,
        filters=filters,
        table=[_summary_row(f) for f in shown],
        finding_ids=[f.finding_id for f in shown],
        total=len(findings),
        caption=f"{len(shown)} trên {len(findings)} phát hiện" + _filter_suffix(filters),
        note=(
            f"Còn {len(findings) - len(shown)} phát hiện nữa không hiện ở đây."
            if len(findings) > len(shown)
            else None
        ),
    )


def lookup(findings: list[Finding], filters: dict[str, str]) -> QueryResult:
    """Same shape as `list_findings` but capped at one row and carrying the full prose, for
    "tell me about finding X" questions."""
    result = list_findings(findings, filters, limit=1)
    result.op = "lookup"
    if result.table:
        finding = next(f for f in findings if f.finding_id == result.table[0]["finding_id"])
        result.table[0]["explanation"] = finding.explanation
        result.table[0]["how_to_verify"] = finding.remediation.how_to_verify
        result.table[0]["how_to_fix"] = finding.remediation.how_to_fix
        result.table[0]["kb_refs"] = list(finding.kb_refs)
    result.caption = "Chi tiết một phát hiện" + _filter_suffix(filters)
    return result


def kb_coverage(findings: list[Finding], filters: dict[str, str]) -> QueryResult:
    """How many findings cite at least one knowledge-base document. This is the number
    `DEBT.md` is about, and it is measured here rather than quoted from a report."""
    cited = [f for f in findings if f.kb_refs]
    uncited_cwes = Counter(
        (f.cwe or UNKNOWN_LABEL) for f in findings if not f.kb_refs
    )
    percent = round(100.0 * len(cited) / len(findings), 1) if findings else 0.0
    table = [
        {"label": "có trích dẫn KB", "count": len(cited)},
        {"label": "không trích dẫn KB", "count": len(findings) - len(cited)},
    ]
    return QueryResult(
        op="kb_coverage",
        dimension=None,
        filters=filters,
        table=table,
        finding_ids=[f.finding_id for f in findings],
        total=len(findings),
        caption=f"Độ phủ kho tri thức: {len(cited)}/{len(findings)} ({percent}%)",
        note=(
            "CWE của các phát hiện không trích dẫn được tài liệu nào: "
            + ", ".join(f"{cwe} ×{n}" for cwe, n in uncited_cwes.most_common(8))
            if uncited_cwes
            else None
        ),
    )


def overview(report: AnalysisReport, findings: list[Finding], filters: dict[str, str]) -> QueryResult:
    """The headline numbers, including the run-scoped ones that live in the sidecar. This
    is the only operation that reads `meta`, because it is the only one describing the run
    rather than the findings."""
    meta = report.meta
    severity = Counter(f.severity for f in findings)
    rows: list[dict[str, Any]] = [
        {"label": "Tổng số phát hiện", "value": len(findings)},
        {"label": "Cảnh báo thô đọc vào", "value": meta.alerts_read},
        {"label": "Trùng lặp đã gộp", "value": meta.exact_duplicates_removed},
    ]
    rows += [
        {"label": f"Mức {level}", "value": severity.get(level, 0)}
        for level in SEVERITY_ORDER
        if severity.get(level, 0)
    ]
    rows += [
        {
            "label": "Không có phân tích mô hình (fallback)",
            "value": sum(1 for f in findings if f.analysis_source == "fallback"),
        },
        {"label": "Trạng thái lần chạy", "value": meta.status},
        {"label": "Mô hình", "value": meta.model or "không dùng mô hình"},
        {"label": "Token đã dùng", "value": meta.total_tokens if meta.total_tokens is not None else "—"},
        {"label": "Sinh lúc", "value": meta.generated_at},
    ]
    return QueryResult(
        op="overview",
        dimension=None,
        filters=filters,
        table=rows,
        finding_ids=[f.finding_id for f in findings],
        total=len(findings),
        caption="Tổng quan báo cáo" + _filter_suffix(filters),
    )


def _filter_suffix(filters: dict[str, str]) -> str:
    if not filters:
        return ""
    return " (lọc: " + ", ".join(f"{k}={v}" for k, v in sorted(filters.items())) + ")"


def run_query(report: AnalysisReport, spec: QuerySpec) -> QueryResult:
    """The one dispatcher. Validates, filters, then hands off to a named function — there
    is no path from a spec string to arbitrary code."""
    spec = validate_spec(spec)
    findings = apply_filters(report.findings, spec.filters)

    if spec.op == "overview":
        return overview(report, findings, spec.filters)
    if spec.op == "count_by":
        return count_by(findings, spec.dimension or "severity", spec.filters)
    if spec.op == "matrix":
        return matrix(findings, spec.filters)
    if spec.op == "top_files":
        return top_files(findings, spec.filters, spec.limit)
    if spec.op == "list_findings":
        return list_findings(findings, spec.filters, spec.limit)
    if spec.op == "lookup":
        return lookup(findings, spec.filters)
    if spec.op == "kb_coverage":
        return kb_coverage(findings, spec.filters)
    raise QuerySpecError(f"thao tác chưa được cài đặt: {spec.op!r}")


# --- deterministic router ---------------------------------------------------------

# Vietnamese first, English second — the report is Vietnamese but the CWE/OWASP vocabulary
# and the file names are not. Order matters: the first matching rule wins, so the more
# specific patterns are listed above the general ones.
_DIMENSION_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("severity", ("mức độ", "muc do", "nghiêm trọng", "nghiem trong", "severity")),
    ("owasp", ("owasp", "top 10", "top10")),
    ("cwe", ("cwe", "loại lỗi", "loai loi", "kiểu lỗi", "kieu loi")),
    ("confidence", ("tin cậy", "tin cay", "confidence")),
    ("tool", ("công cụ", "cong cu", "tool", "semgrep", "metis")),
    ("analysis_source", ("fallback", "dự phòng", "du phong", "nguồn phân tích", "mô hình hay")),
)

_MATRIX_KEYWORDS = ("ma trận", "ma tran", "matrix", "bảng chéo", "bang cheo", "chéo", "cheo")
_FILE_KEYWORDS = ("tệp", "tep", "file", "tập tin", "tap tin", "đường dẫn", "duong dan")
_KB_KEYWORDS = ("kho tri thức", "kho tri thuc", "knowledge base", "trích dẫn", "trich dan", "kb")
_OVERVIEW_KEYWORDS = ("tổng quan", "tong quan", "tóm tắt", "tom tat", "overview", "tổng cộng", "tong cong")
_LIST_KEYWORDS = ("liệt kê", "liet ke", "danh sách", "danh sach", "cho tôi xem", "list", "những lỗi", "nhung loi")
_COUNT_KEYWORDS = ("bao nhiêu", "bao nhieu", "đếm", "dem", "số lượng", "so luong", "phân bố", "phan bo", "thống kê", "thong ke")

_SEVERITY_KEYWORDS = {
    "critical": ("critical", "nghiêm trọng nhất", "nguy kịch"),
    "high": ("high", "cao"),
    "medium": ("medium", "trung bình", "trung binh"),
    "low": ("low", "thấp", "thap"),
}


def _extract_filters(question: str) -> dict[str, str]:
    lowered = question.lower()
    filters: dict[str, str] = {}

    cwe = _CWE_RE.search(lowered)
    if cwe:
        filters["cwe"] = f"CWE-{cwe.group(1)}"

    finding_id = _FINDING_ID_RE.search(lowered)
    if finding_id and not cwe:
        filters["text"] = finding_id.group(1)

    for level, needles in _SEVERITY_KEYWORDS.items():
        if any(needle in lowered for needle in needles):
            filters["severity"] = level
            break

    java_file = re.search(r"\b([\w./-]*BenchmarkTest\w*(?:\.java)?)", question, re.IGNORECASE)
    if java_file:
        filters["file"] = java_file.group(1)

    return filters


def route_keywords(question: str) -> QuerySpec:
    """The deterministic router. Always returns a runnable spec — a question it cannot
    place becomes an `overview`, which is a real answer rather than an error, and the chat
    layer says out loud that keyword routing was used.

    This is also the fallback the deployed instance runs on permanently, since it holds no
    model credentials (ADR 19). Answers there are narrower, never absent."""
    lowered = question.lower().strip()
    filters = _extract_filters(question)

    if any(needle in lowered for needle in _KB_KEYWORDS):
        return validate_spec(QuerySpec(op="kb_coverage", filters=filters))

    # Above the dimension loop on purpose: "ma trận mức độ và độ tin cậy" contains both
    # dimension keywords, and the first of them would otherwise win and answer with a
    # one-dimensional bar chart — half the question.
    if any(needle in lowered for needle in _MATRIX_KEYWORDS):
        return validate_spec(QuerySpec(op="matrix", filters=filters))

    # "tệp nào nhiều lỗi nhất" ranks files; "lỗi trong tệp X" is about one named file, and
    # ranking would answer a question nobody asked. A concrete file filter wins.
    if any(needle in lowered for needle in _FILE_KEYWORDS) and "file" not in filters:
        return validate_spec(QuerySpec(op="top_files", filters=filters, limit=DEFAULT_LIMIT))

    # A bare finding id is a lookup, not a listing.
    if _FINDING_ID_RE.search(lowered) and not _CWE_RE.search(lowered):
        return validate_spec(QuerySpec(op="lookup", filters=filters))

    for dimension, needles in _DIMENSION_KEYWORDS:
        if not any(needle in lowered for needle in needles):
            continue
        # A dimension the question already pinned to a value is not a dimension to group
        # by. "liệt kê lỗi CWE-89" mentions `cwe`, but it asks about one CWE — answering
        # with a distribution across all 25 of them would be a different question.
        if dimension in filters:
            break
        return validate_spec(QuerySpec(op="count_by", dimension=dimension, filters=filters))

    if any(needle in lowered for needle in _LIST_KEYWORDS):
        return validate_spec(QuerySpec(op="list_findings", filters=filters, limit=DEFAULT_LIMIT))

    if any(needle in lowered for needle in _COUNT_KEYWORDS):
        return validate_spec(QuerySpec(op="count_by", dimension="severity", filters=filters))

    if any(needle in lowered for needle in _OVERVIEW_KEYWORDS):
        return validate_spec(QuerySpec(op="overview", filters=filters))

    # A question carrying a concrete filter but no recognisable verb is most usefully a
    # listing of what matched.
    if filters:
        return validate_spec(QuerySpec(op="list_findings", filters=filters, limit=DEFAULT_LIMIT))

    return validate_spec(QuerySpec(op="overview"))


# --- deterministic narration ------------------------------------------------------


def template_answer(result: QueryResult) -> str:
    """A Vietnamese sentence built from the table alone. Used when no model is available
    and whenever a model narration fails, so an answer is never missing — only plainer."""
    if result.total == 0:
        return (
            "Không có phát hiện nào khớp với điều kiện này. "
            "Lưu ý: điều đó có nghĩa là *bộ lọc không khớp gì*, không phải là *không có lỗ hổng*."
        )

    if result.op == "count_by":
        parts = [f"**{row['label']}**: {row['count']}" for row in result.table if row["count"]]
        return (
            f"Trong {result.total} phát hiện, phân bố theo `{result.dimension}` là — "
            + ", ".join(parts)
            + "."
        )

    if result.op == "matrix":
        # Name the single largest cell rather than reciting the grid: the table is right
        # underneath, and what it does not say out loud is where the mass actually sits.
        cells = [
            (row["label"], column, row[column])
            for row in result.table
            for column in result.columns
            if row[column]
        ]
        top_level, top_column, top_count = max(cells, key=lambda cell: cell[2])
        return (
            f"Ma trận `{MATRIX_ROW}` × `{MATRIX_COLUMN}` trên {result.total} phát hiện. "
            f"Ô lớn nhất là mức **{top_level}** với độ tin cậy **{top_column}**: "
            f"{top_count} phát hiện."
        )

    if result.op == "top_files":
        if not result.table:
            return f"{result.total} phát hiện nhưng không có vị trí tệp nào được ghi lại."
        top = result.table[0]
        return (
            f"Tệp bị nhiều phát hiện nhất là `{top['label']}` với {top['count']} phát hiện. "
            f"Bảng dưới liệt kê {len(result.table)} tệp đầu bảng."
        )

    if result.op == "list_findings":
        return (
            f"Có {result.total} phát hiện khớp; bảng dưới hiện {len(result.table)} phát hiện, "
            "xếp theo mức độ nghiêm trọng rồi tới số lần xuất hiện."
        )

    if result.op == "lookup":
        if not result.table:
            return "Không tìm thấy phát hiện nào khớp."
        row = result.table[0]
        return (
            f"**{row['title']}** — mức `{row['severity']}`, độ tin cậy `{row['confidence']}`, "
            f"{row['cwe']}, xuất hiện {row['occurrences']} lần trên {row['files']} tệp."
        )

    if result.op == "kb_coverage":
        cited = result.table[0]["count"]
        return (
            f"{cited} trên {result.total} phát hiện trích dẫn được ít nhất một tài liệu "
            "trong kho tri thức. Phần còn lại vẫn được truy hồi tài liệu nhưng mô hình "
            "không trích dẫn cái nào — đây là thước đo độ phủ của kho tri thức, không phải "
            "chất lượng phân tích."
        )

    # overview
    lines = [f"- {row['label']}: **{row['value']}**" for row in result.table]
    return "Tổng quan báo cáo hiện tại:\n" + "\n".join(lines)
