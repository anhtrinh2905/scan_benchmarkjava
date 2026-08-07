"""Streamlit control panel for the Metis/BenchmarkJava scan harness.

Run config (C-002), background execution (C-003), and results viewer (C-004) below.
UI reorganized into a sidebar-navigated, multipage layout (Run Scan / Results /
Security Report / Knowledge Base) — all `scan_runner`/`kb_search` calls and their
contracts are unchanged; this is a presentation-layer restructure only.

C-012 added the deploy surface: a read-only Run Scan page, backed by `scan_runner`'s own
refusal to spawn. C-013 removed the password gate that shipped alongside it — the
deployed instance is public by decision (ADR 19); what keeps it safe is that it cannot
act, not that it is hard to reach.

C-014 (v1.5) added the Matrix page — one cross-run table, 100 test files by 15 runs
(FR14) — and rebuilt Results as a metrics-first grid (FR15). The Matrix page was later
removed from the nav by request; Results still reads only through the `scan_runner` seam,
so this file opens no file under `results/` and parses no run JSON. The cross-run seam
(`scan_runner.load_matrix`, `filter_matrix`, `matrix_records`, `matrix_categories`) is
left in place but no longer called from anywhere — FR14 has no surface in the UI now.

C-019 (v1.7) added the Security Report page (FR22). Same rule again: its only data source
is `security_agent.load_report()`. This file never opens the generated report, never parses
it, and never calls the analysis endpoint — the deployed instance holds no key and renders a
report baked into the image at build time.

C-021 (v1.9) reorganized around what the site is actually for. The nav is three entries —
Security Report, Comparison (formerly Results), Knowledge Base — with Security Report as the
landing page, and its tabs are Hỏi đáp then Tổng quan, so a visitor lands on the question box.
The separate findings-list tab is gone: the list now sits under the chat and an answer can
scope it to its own evidence. The suggested questions are served from `report_chat`'s prebaked
cache, which is why they return in milliseconds; every answer prints the model, tokens and
wall-clock that produced it. This file still computes nothing — `report_query` counts, and
`report_chat` decides what a turn cost.
"""
import json
import os
import shlex
from dataclasses import asdict

import pandas as pd
import streamlit as st

import report_charts
import report_chat
import report_query
import scan_runner
import security_agent
from kb_search import search_kb

STATUS_STATE = {"running": "running", "done": "complete", "failed": "error"}
STATUS_LABEL = {"running": "Scan running", "done": "Scan complete", "failed": "Scan failed"}
STATUS_ICON = {
    "running": ":material/progress_activity:",
    "done": ":material/check_circle:",
    "failed": ":material/error:",
}

KIND_LABEL = {"bench": "Benchmark", "sweep": "Sweep", "ablation": "Ablation"}
# What one row of that kind's compare table is, in the words the scorecard uses.
KIND_UNIT = {"bench": "run", "sweep": "variant", "ablation": "arm"}

# The one stylesheet in this app, and it exists to contain a single failure mode.
#
# A scorecard is a document, and some of its tables are wider than the column they are
# rendered into — ablation's compare table is ten columns. Streamlit sizes a markdown
# table to its content and the column around it does not clip, so an over-wide table
# used to paint straight across the panel beside it. Scrolling it inside its own box is
# the standard fix (ux: table-handling): the table wraps to fit when it can, scrolls
# when it cannot, and never moves anything else on the page.
PAGE_CSS = """
<style>
/* `st.html` lands as a real element in the vertical flow, and a stylesheet is not
   content — left visible it opens a gap above every page title. */
[data-testid="stElementContainer"]:has(> [data-testid="stHtml"] > style) {
    display: none;
}

[data-testid="stMarkdownContainer"] table {
    display: block;
    width: fit-content;
    max-width: 100%;
    overflow-x: auto;
}
/* Figures in a column should read as a column — same-width digits, no jitter row to
   row (typography: number-tabular). */
[data-testid="stMarkdownContainer"] table td,
[data-testid="stMarkdownContainer"] table th {
    font-variant-numeric: tabular-nums;
}
</style>
"""

# The severity scale, declared once in DESIGN.md (2026-08-06). Colour is reinforcement
# only, so every badge also prints its literal word. (The TP/TN/FN/FP outcome scale that
# used to live here went with the Matrix page — DESIGN.md still declares it, and it is
# where to look if that table ever comes back.)
SEVERITY_STYLE = {
    "critical": ("#FEF2F2", "#991B1B"),
    "high": ("#FFF7ED", "#9A3412"),
    "medium": ("#FEFCE8", "#854D0E"),
    "low": ("#F0F9FF", "#075985"),
    "info": ("#F4F4F5", "#52525B"),
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
CONFIDENCE_ORDER = ["high", "medium", "low"]

# Cell tints for the severity × confidence grid, lightest to darkest. Four steps, not a
# continuous gradient: a reader compares cells against each other, and four distinguishable
# bands do that where 93 shades of blue do not. Every cell prints its count either way —
# the tint is the same law as the outcome table, reinforcement and never the information.
MATRIX_TINTS = ("#F5F7FC", "#E6EBF7", "#CFD9EF", "#B2C1E4")
MATRIX_ZERO_STYLE = "color:#A1A1AA"


def render_readonly_run_notice() -> None:
    st.title("Run Scan")
    st.caption("Not available on this instance.")
    with st.container(border=True):
        st.markdown(
            "This is a shared, read-only copy of the control panel. It holds no model "
            "credentials and cannot start a scan, so nothing here can spend LLM budget."
        )
        st.markdown(
            "**Security Report**, **Comparison** and **Knowledge Base** show real output "
            "from scans already run. To run a new scan, use a local checkout:"
        )
        st.code(
            "uv sync\nuv run streamlit run app.py   # http://localhost:8501",
            language="bash",
        )


def _plural(count: int, unit: str) -> str:
    return unit if count == 1 else f"{unit}s"


def render_progress_bar(status: scan_runner.RunStatus) -> None:
    """The FR16 bar. Absent — not zeroed, not animated — when the seam reports no
    countable signal, so the page never implies a measurement nobody made."""
    progress = status.progress
    if progress is None:
        st.caption(
            "Waiting for the first countable step — the log below is live in the meantime."
        )
        return

    st.progress(progress.fraction)
    done_text = f"**{progress.done} / {progress.total}** {_plural(progress.total, progress.unit)}"
    if status.state == "running" and progress.current:
        st.caption(f"{done_text} · now scanning `{progress.current}`")
    elif status.state == "running":
        st.caption(f"{done_text} · starting…")
    else:
        st.caption(done_text)


@st.fragment(run_every=1)
def render_run_progress(handle: scan_runner.RunHandle) -> None:
    status = scan_runner.poll_run(handle)
    label = STATUS_LABEL[status.state]
    if status.progress is not None and status.state == "running":
        label += f" — {status.progress.done}/{status.progress.total}"
    if status.returncode is not None:
        label += f" (exit code {status.returncode})"
    with st.status(label, state=STATUS_STATE[status.state], expanded=status.state != "done"):
        render_progress_bar(status)
        st.code(status.log_tail or "(no output yet)", language=None)


@st.fragment(run_every=1)
def render_active_run_badge() -> None:
    handle = st.session_state.get("run_handle")
    if handle is None:
        st.caption("No active run")
        return
    status = scan_runner.poll_run(handle)
    st.markdown(f"{STATUS_ICON[status.state]} **{STATUS_LABEL[status.state]}**")
    # The badge is on every page, so a run stays watchable while reading Results — the
    # same counted numbers, no second source of truth.
    if status.progress is not None:
        st.progress(status.progress.fraction)
        st.caption(
            f"{status.progress.done} / {status.progress.total} "
            f"{_plural(status.progress.total, status.progress.unit)}"
        )
    st.caption(shlex.join(handle.command))


def page_run_scan() -> None:
    if scan_runner.runtime_mode() == "readonly":
        render_readonly_run_notice()
        return

    st.title("Run Scan")
    st.caption("Configure, review, and launch a Metis vs OWASP BenchmarkJava scan.")

    with st.container(border=True):
        st.subheader("Configuration")
        left, right = st.columns(2)
        with left:
            kind = st.selectbox("Scan type", options=["bench", "sweep", "ablation"], key="run_kind")
            sample = st.slider("Sample size", min_value=1, max_value=100, value=6, key="run_sample")
        with right:
            known_only = scan_runner.known_only_values(kind)
            if known_only:
                only = st.multiselect("Variant / arm (--only)", options=known_only, key="run_only")
            else:
                only = []
                st.caption(
                    "bench.py's `--only` matches test-name substrings, not a fixed list — "
                    "leave unset here and pass it on the CLI directly if needed."
                )
            tag = st.text_input("Tag (--tag)", value="baseline", key="run_tag") if kind == "bench" else None

    command = scan_runner.build_command(kind, only or None, sample, tag)

    with st.container(border=True):
        st.subheader("Review & confirm")
        st.code(shlex.join(command), language="bash")

        cost = scan_runner.estimate_cost(kind, sample, only or None)
        if cost.warning_text:
            st.warning(cost.warning_text, icon=":material/warning:")

        st.session_state.setdefault("confirmed_command", None)
        st.session_state.setdefault("run_handle", None)

        confirm_col, start_col = st.columns(2)
        with confirm_col:
            if st.button("Confirm run", width="stretch"):
                st.session_state.confirmed_command = command
        is_confirmed = st.session_state.confirmed_command == command
        with start_col:
            if st.button(
                "Start run", type="primary", disabled=not is_confirmed, width="stretch"
            ):
                st.session_state.run_handle = scan_runner.start_run(command)
        if not is_confirmed:
            st.caption("Confirm the command above to enable the run trigger.")

    if st.session_state.get("run_handle") is not None:
        st.subheader("Live progress")
        render_run_progress(st.session_state.run_handle)


def _pct(value: float | None) -> str:
    return f"{value * 100:.1f}%" if value is not None else "—"


def _count(value: int | None) -> str:
    return f"{value:,}" if value is not None else "—"


def render_result_kpis(metrics: scan_runner.RunMetrics) -> None:
    """The headline numbers, above any prose (FR15). Two rows of five: quality first
    (what the run got right), then cost (what it took to get there) — the order the
    scorecard argues in, but readable without scrolling into it.

    No `delta=` on any of these. A delta renders with an up/down arrow, which states a
    change against a previous value; TP/FN/FP/TN are four parts of one snapshot, and
    "↑ 3 missed" would assert a trend this page has no second run to measure."""
    quality = st.columns(5)
    quality[0].metric("Precision", _pct(metrics.precision_strict), border=True)
    quality[1].metric("Recall", _pct(metrics.recall_strict), border=True)
    quality[2].metric("Caught", _count(metrics.tp),
                      help="TP — real vulnerabilities reported.", border=True)
    quality[3].metric("Missed", _count(metrics.fn),
                      help="FN — real vulnerabilities never reported.", border=True)
    quality[4].metric("False alarms", _count(metrics.fp),
                      help="FP — safe files reported as vulnerable.", border=True)

    cost = st.columns(5)
    cost[0].metric("Correctly clean", _count(metrics.tn),
                   help="TN — safe files correctly left alone.", border=True)
    cost[1].metric("Findings (raw)", _count(metrics.findings), border=True)
    cost[2].metric(
        "Wall-clock", f"{metrics.minutes:g} min" if metrics.minutes is not None else "—",
        border=True,
    )
    tokens = metrics.total_tokens
    cost[3].metric(
        "Tokens", f"{tokens / 1_000_000:.2f}M" if tokens else _count(tokens), border=True
    )
    cost[4].metric("Test files", _count(metrics.sample_size), border=True)


def scorecard_body(markdown: str) -> str:
    """Drop the scorecard's own leading `# ` title. The page already says Results and the
    Run details panel already names the run, so rendering it would put a third, larger
    heading above content that is subordinate to both."""
    lines = markdown.splitlines()
    if lines and lines[0].startswith("# "):
        return "\n".join(lines[1:]).lstrip("\n")
    return markdown


def render_run_metadata(kind: str, name: str, metrics: scan_runner.RunMetrics | None) -> None:
    """What produced these numbers, as one strip directly under the run picker.
    Machine-shaped values stay mono (DESIGN.md).

    This used to be a side panel beside the scorecard, which cost the scorecard ~30% of
    the page and put a narrow column exactly where the widest table needed room. It is
    six short, fixed-length facts that identify the run just picked, so it reads better
    beside the picker than beside the document — and label-above-value puts every label
    on one baseline, which stacked `st.columns([1, 1.4])` rows never managed."""
    rows = [("Scan type", KIND_LABEL.get(kind, kind)), ("Run", f"`{name}`")]
    if metrics:
        if metrics.scan_model:
            rows.append(("Scan model", f"`{metrics.scan_model}`"))
        if metrics.metis_version:
            rows.append(("Metis", f"`v{metrics.metis_version}`"))
        if metrics.triage is not None:
            rows.append(("Triage", "on" if metrics.triage else "off"))
        if metrics.generated_at:
            rows.append(("Ran at", f"`{metrics.generated_at[:19].replace('T', ' ')}`"))
    with st.container(border=True):
        for column, (label, value) in zip(st.columns(len(rows)), rows):
            column.caption(label)
            column.markdown(value)


# The batch compare table reaches this file as raw CSV rows, so every value is a string:
# a precision column printed `0.9666666666666667`, a token count with no separators, and
# headers still carrying the column names the scripts write. Declare each known column's
# label and shape once here, and let `st.column_config` do the rendering — same numbers,
# read at a glance. An unknown column still renders; it just falls back to plain text.
COMPARE_COLUMNS = {
    "arm": ("Arm", "text"),
    "variant": ("Variant", "text"),
    "youden_strict": ("Youden (strict)", "percent"),
    "youden_lenient": ("Youden (lenient)", "percent"),
    "precision": ("Precision", "percent"),
    "recall": ("Recall", "percent"),
    "gt_precision": ("Precision", "percent"),
    "gt_recall": ("Recall", "percent"),
    "fpr": ("FPR", "percent"),
    "triage_prec": ("Triage precision", "percent"),
    "youden_per_1m": ("Youden / 1M tokens", "score"),
    "total_tokens": ("Tokens", "count"),
    "findings": ("Findings (raw)", "count"),
    "gt_tp": ("Caught (TP)", "count"),
    "gt_fp": ("False alarms (FP)", "count"),
    "gt_fn": ("Missed (FN)", "count"),
    "gt_tn": ("Correctly clean (TN)", "count"),
    "minutes": ("Wall-clock (min)", "minutes"),
    "pareto": ("Pareto", "flag"),
    "error": ("Error", "text"),
}
NUMBER_FORMAT = {"percent": "%.1f%%", "score": "%.1f", "count": "localized", "minutes": "%.1f"}
# One decimal, and Youden/1M read on the same 0-100 point scale the scorecard prints it
# on. Two tables on one page describing the same run must not appear to disagree.
SCALE_BY_100 = {"percent", "score"}


def compare_table(rows: list[dict]) -> tuple[pd.DataFrame, dict]:
    """The batch compare rows as a typed frame plus its column config."""
    frame = pd.DataFrame(rows)
    # A column empty in every row is a header with nothing under it — sweep records no
    # `triage_prec`, and a finished run records no `error`. Drop it rather than print a
    # column of blanks that reads as missing data.
    frame = frame[[name for name in frame.columns if frame[name].astype(str).str.strip().any()]]

    config: dict = {}
    for position, name in enumerate(frame.columns):
        label, shape = COMPARE_COLUMNS.get(name, (name.replace("_", " ").capitalize(), "text"))
        if shape == "text":
            config[name] = st.column_config.TextColumn(label, pinned=position == 0)
        elif shape == "flag":
            frame[name] = frame[name].astype(str).str.strip().str.lower().isin({"true", "1", "yes"})
            config[name] = st.column_config.CheckboxColumn(
                label, help="No other row is both higher-scoring and cheaper."
            )
        else:
            numeric = pd.to_numeric(frame[name], errors="coerce")
            frame[name] = numeric * 100 if shape in SCALE_BY_100 else numeric
            config[name] = st.column_config.NumberColumn(label, format=NUMBER_FORMAT[shape])
    return frame, config


def page_results() -> None:
    st.title("Comparison")
    st.caption("One run at a time — scorecard, headline numbers, and how it was produced.")

    # Step 1 of the picker states what each type holds, so choosing a scan type is an
    # informed click rather than a guess that lands on an empty page.
    counts = {
        kind: len(scan_runner.list_results(kind)) for kind in ("bench", "sweep", "ablation")
    }
    kind = st.segmented_control(
        "Scan type",
        options=["bench", "sweep", "ablation"],
        format_func=lambda k: f"{KIND_LABEL[k]} · {counts[k]}",
        default="bench",
        key="results_kind",
    ) or "bench"

    results = scan_runner.list_results(kind)
    if not results:
        st.info(f"No {kind} results yet — start one from **Run Scan**.", icon=":material/info:")
        return

    run_name = st.selectbox(
        "Run", options=[result.name for result in results], key="results_run_picker"
    )
    bundle = scan_runner.load_result(kind, run_name)
    if bundle.cache_warning:
        st.warning(bundle.cache_warning, icon=":material/warning:")

    render_run_metadata(kind, run_name, bundle.metrics)

    if bundle.metrics:
        render_result_kpis(bundle.metrics)
    else:
        st.caption("This run kept no machine-readable summary — scorecard only.")

    # Full width, and deliberately so: the scorecard is the page's document, and its
    # widest table needs more room than a two-thirds column left it.
    st.subheader("Scorecard")
    if kind != "bench":
        # Neither sweep.py nor ablation.py writes a per-run scorecard, so this one
        # document covers the whole batch. Saying so beats letting the reader wonder why
        # picking a different run left the text unchanged.
        st.caption(
            f"One document for the whole {KIND_LABEL[kind].lower()} batch — every "
            f"{KIND_UNIT[kind]}, not only `{run_name}`."
        )
    with st.container(border=True):
        st.markdown(scorecard_body(bundle.scorecard_md) or "_(no scorecard found for this run)_")

    if bundle.compare_rows is not None:
        # Not "Comparison" — that is the page's own name now, and a section heading that
        # repeats the page title tells the reader nothing about what changed.
        st.subheader("Batch table")
        st.caption(
            f"The same batch as a sortable table — one row per {KIND_UNIT[kind]}, "
            "not per test file."
        )
        frame, column_config = compare_table(bundle.compare_rows)
        st.dataframe(frame, column_config=column_config, hide_index=True, width="stretch")




@st.cache_data(show_spinner=False)
def cached_search_kb(query: str, mode: str, top_k: int, min_score: float) -> list:
    """Memoized `search_kb` so re-runs triggered by opening an expander (or nudging a
    slider back to a previous value) don't recompute — and, in semantic mode, don't
    spend a fresh embeddings call on an identical query."""
    return search_kb(query, mode=mode, top_k=top_k, min_score=min_score)


def render_kb_hit(hit) -> None:
    """One compact result card: title + mono identifiers, the vulnerable snippet for
    `examples` docs, and the full document behind an in-place expander."""
    with st.container(border=True):
        st.markdown(f"**{hit.title}**")
        st.caption(f"`{hit.doc_id}` · score `{hit.score:.3f}`")
        if hit.vulnerable_code:
            st.code(hit.vulnerable_code, language="java")
        else:
            st.caption(hit.snippet)
        with st.expander("Full document"):
            st.markdown(hit.body)


def render_kb_category(hits: list, category: str) -> None:
    items = [hit for hit in hits if hit.category == category]
    st.markdown(f"**{KB_CATEGORY_LABEL.get(category, category)}** · `{len(items)}`")
    if not items:
        st.caption("No matches in this category above the current threshold.")
        return
    for hit in items:
        render_kb_hit(hit)


def submit_kb_query() -> None:
    """Pressing Enter in the query box runs the search, exactly as the button does.

    Without this, Enter reruns the script with nothing to show for it — the field looks
    broken to anyone who types a query and hits Enter, which is most people
    (forms: submit-feedback)."""
    query = st.session_state.get("kb_query", "").strip()
    if query:
        st.session_state.kb_active_query = query


# The KB's own folder names are not user words (DESIGN.md rule 4).
KB_CATEGORY_LABEL = {
    "examples": "Vulnerable code examples",
    "owasp-top10": "OWASP Top 10",
    "rules": "Detection rules",
}


def page_knowledge_base() -> None:
    st.title("Knowledge Base")
    st.caption("Search vulnerability documentation by keyword or semantic similarity.")

    with st.container(border=True):
        query_col, mode_col = st.columns([3, 1])
        with query_col:
            kb_query = st.text_input(
                "Query",
                placeholder="e.g. SQL injection, weak randomness…",
                key="kb_query",
                label_visibility="collapsed",
                on_change=submit_kb_query,
            )
        with mode_col:
            kb_mode = st.segmented_control(
                "Mode", options=["keyword", "semantic"], default="keyword", key="kb_mode"
            ) or "keyword"
        search_clicked = st.button("Search", type="primary", icon=":material/search:")

        # Defaults beat configuration (DESIGN.md rule 3) — the two tuning knobs stay
        # behind one disclosure so the default path is just query + mode + Search.
        with st.expander("Search options"):
            top_k = st.slider("Result limit (top-k)", 1, 20, 5, key="kb_top_k")
            min_score = st.slider(
                "Minimum similarity", 0.0, 1.0, 0.1, step=0.05, key="kb_min_score"
            )
            st.caption(
                "Keyword scores run low (a strong match is often ~0.35), so a high "
                "threshold will empty the results. Semantic scores run higher."
            )

    # Persist the searched query: opening an expander or moving a slider re-runs the
    # script, and without this the results would vanish on the first interaction.
    if search_clicked and kb_query.strip():
        st.session_state.kb_active_query = kb_query.strip()
    active_query = st.session_state.get("kb_active_query")
    if not active_query:
        return

    hits = cached_search_kb(active_query, kb_mode, top_k, min_score)
    if not hits:
        st.info(
            f"No KB docs matched “{active_query}” at similarity ≥ {min_score:.2f}.",
            icon=":material/info:",
        )
        return

    examples_col, side_col = st.columns([2, 1], gap="medium")
    with examples_col:
        render_kb_category(hits, "examples")
    with side_col:
        render_kb_category(hits, "owasp-top10")
        render_kb_category(hits, "rules")


# --------------------------------------------------------------------------
# Security Report (C-019, FR22)
# --------------------------------------------------------------------------


def severity_badge(severity: str) -> str:
    """A tinted chip that always carries its literal word. The tint is reinforcement; the
    word is the information (DESIGN.md severity scale, WCAG `color-not-only`)."""
    background, foreground = SEVERITY_STYLE.get(severity, SEVERITY_STYLE["info"])
    return (
        f'<span style="background-color:{background};color:{foreground};font-weight:600;'
        f'padding:1px 8px;border-radius:4px;font-size:0.85em">{severity}</span>'
    )


def filter_findings(findings: list, severities: list, confidences: list, query: str) -> list:
    """Pure. Takes the loaded findings and the three controls, returns what to show —
    no session state, no I/O, so the visible count is always a function of the filters."""
    text = query.strip().lower()
    kept = []
    for finding in findings:
        if severities and finding.severity not in severities:
            continue
        if confidences and finding.confidence not in confidences:
            continue
        if text:
            haystack = " ".join(
                [finding.title, finding.cwe or ""]
                + [location.file for location in finding.locations]
            ).lower()
            if text not in haystack:
                continue
        kept.append(finding)
    return kept


def findings_as_jsonl(findings: list) -> str:
    """The same one-object-per-line shape `write_report()` produces, rebuilt from the
    findings already in hand. The page does not read the generated file to serve it."""
    return "".join(
        json.dumps(asdict(finding), ensure_ascii=False, sort_keys=True) + "\n"
        for finding in findings
    )


def render_report_status_banner(meta) -> None:
    """A run that degraded must not look clean on screen either — the same honesty the
    sidecar carries, at the top of the page rather than buried in a download."""
    if meta.status == "ok":
        return
    if meta.status == "degraded":
        reasons = ", ".join(f"{k}: {v}" for k, v in meta.llm_failure_reasons.items())
        st.error(
            f"Báo cáo này ở trạng thái **degraded** — mọi nhóm đều phải rơi về phân tích "
            f"dự phòng, không có phân tích nào từ mô hình. Lý do: {reasons or 'không rõ'}.",
            icon=":material/error:",
        )
    elif meta.status == "invalid_input":
        st.error(
            f"Đầu vào hỏng hoàn toàn: {meta.alerts_skipped}/{meta.alerts_read} dòng bị bỏ "
            "qua, không có phát hiện nào được ghi.",
            icon=":material/error:",
        )
    elif meta.status == "empty":
        st.warning(
            "Đầu vào rỗng — đây KHÔNG có nghĩa là không tìm thấy lỗ hổng nào.",
            icon=":material/warning:",
        )


def render_report_kpis(report) -> None:
    meta = report.meta
    by_severity = {level: 0 for level in SEVERITY_ORDER}
    fallback_count = 0
    for finding in report.findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        if finding.analysis_source == "fallback":
            fallback_count += 1

    headline = st.columns(3)
    headline[0].metric("Phát hiện", _count(len(report.findings)), border=True)
    headline[1].metric(
        "Từ cảnh báo", f"{meta.alerts_read} → {len(report.findings)}",
        help="Số dòng cảnh báo đọc vào, gộp thành số phát hiện.", border=True,
    )
    headline[2].metric(
        "Không có phân tích mô hình", _count(fallback_count),
        help="Phát hiện chỉ có nội dung dự phòng (fallback), mô hình không đóng góp gì.",
        border=True,
    )

    severity_row = st.columns(len(SEVERITY_ORDER))
    for column, level in zip(severity_row, SEVERITY_ORDER):
        column.metric(level, _count(by_severity[level]), border=True)


def matrix_cell_style(count: int, largest: int) -> str:
    """The tint for one grid cell. A zero is greyed rather than tinted — an empty cell must
    read as empty, not as the palest band of 'some'."""
    if count <= 0 or largest <= 0:
        return MATRIX_ZERO_STYLE
    band = min(len(MATRIX_TINTS) - 1, (count * len(MATRIX_TINTS) - 1) // largest)
    return f"background-color:{MATRIX_TINTS[band]};color:#1E293B;font-weight:600"


def render_severity_confidence_matrix(report) -> None:
    """Severity against confidence, one grid.

    The two bar charts below already show each axis on its own, and neither can be crossed
    with the other after the fact: nothing in them says how many `high` findings are also
    `low` confidence. That cell is the one worth reading first — it is the pile that looks
    urgent and may not survive a look at the evidence.

    Every number here is counted by `report_query.matrix()`. This function picks colours
    and column labels; it does not add anything up."""
    try:
        result = report_query.run_query(report, report_query.QuerySpec(op="matrix"))
    except report_query.QuerySpecError as exc:
        st.warning(f"Không dựng được ma trận ({exc})")
        return

    st.markdown("### Ma trận mức độ × độ tin cậy")
    st.caption(
        "Cả hai trục đều do Python quyết định: mức độ bị kẹp trong ±1 bậc so với mức công "
        "cụ quét báo, độ tin cậy bị ép sàn khi bằng chứng mỏng. Ô **mức cao / tin cậy "
        "thấp** là nhóm trông khẩn cấp nhưng bằng chứng yếu — thường nên xem trước."
    )

    if not result.table:
        st.info(
            "Báo cáo không có phát hiện nào để xếp vào ma trận. Đây là *báo cáo rỗng*, "
            "không phải *không có lỗ hổng*.",
            icon=":material/info:",
        )
        return

    columns = result.columns
    frame = pd.DataFrame(result.table)[["label", *columns, "count"]]
    # The scale for the tint bands is the largest single cell, so the darkest band always
    # exists and the row-total column never washes the grid out by dominating it.
    largest = max(int(frame[column].max()) for column in columns)

    styled = frame.style.map(
        lambda value: matrix_cell_style(int(value), largest), subset=columns
    ).map(
        lambda value: "background-color:{};color:{};font-weight:600".format(
            *SEVERITY_STYLE.get(value, SEVERITY_STYLE["info"])
        ),
        subset=["label"],
    )

    column_config = {
        "label": st.column_config.TextColumn("Mức độ", pinned=True, width="small"),
        "count": st.column_config.NumberColumn(
            "Tổng", width="small", help="Tổng số phát hiện ở mức này, cộng ngang."
        ),
    }
    for column in columns:
        column_config[column] = st.column_config.NumberColumn(
            f"Tin cậy {column}",
            width="small",
            help=f"Phát hiện có độ tin cậy `{column}` ở mức tương ứng.",
        )

    st.dataframe(
        styled,
        column_config=column_config,
        hide_index=True,
        height=45 + 35 * len(frame),
        width="stretch",
    )
    if result.note:
        st.caption(result.note)
    st.caption(
        f"Tổng cộng {result.total} phát hiện — mỗi phát hiện nằm ở đúng một ô, "
        "nên các ô cộng lại đúng bằng con số **Phát hiện** ở trên."
    )


def render_finding_body(finding) -> None:
    if finding.analysis_source == "fallback":
        st.warning(
            "Không có phân tích từ mô hình cho nhóm này — nội dung dưới đây được dựng "
            "từ chính cảnh báo của công cụ quét và tài liệu KB.",
            icon=":material/info:",
        )

    st.markdown("**Vị trí**")
    locations = finding.locations
    if len(locations) > 5:
        st.caption(f"{len(locations)} vị trí")
        with st.expander(f"Xem đủ {len(locations)} vị trí"):
            for location in locations:
                st.markdown(f"- `{location.file}`" + (f" : {location.line}" if location.line else ""))
    else:
        for location in locations:
            st.markdown(f"- `{location.file}`" + (f" : {location.line}" if location.line else ""))

    st.markdown("**Bằng chứng từ công cụ quét**")
    st.caption(
        f"công cụ `{finding.evidence.tool}` · {finding.evidence.occurrence_count} lần xuất hiện "
        f"trên {finding.evidence.files_affected} tệp"
        + (f" · rule `{finding.evidence.rule_id}`" if finding.evidence.rule_id else "")
    )
    st.code(finding.evidence.raw_message, language=None)

    st.markdown("**Giải thích**")
    st.markdown(finding.explanation)

    st.markdown("**Cách kiểm tra**")
    st.markdown(finding.remediation.how_to_verify)

    st.markdown("**Cách khắc phục**")
    st.markdown(finding.remediation.how_to_fix)
    if finding.remediation.code_hint:
        st.code(finding.remediation.code_hint, language="java")

    st.markdown("**Tài liệu KB**")
    if finding.kb_refs:
        for doc_id in finding.kb_refs:
            st.markdown(f"- `{doc_id}`")
        st.caption("Tra cứu toàn văn ở trang Knowledge Base.")
    else:
        st.caption("Không có tài liệu KB nào khớp — độ tin cậy đã bị hạ tương ứng.")

    st.markdown("**Mức độ tin cậy**")
    st.markdown(f"`{finding.confidence}` — {finding.confidence_reason}")


def render_query_result(result, key: str) -> None:
    """One `QueryResult`, rendered the same way everywhere it appears: chart on top when
    the result is a distribution, the numbers underneath it always.

    The table is not optional decoration. It is what makes a claim on this page checkable —
    the chart, the prose in the chat tab, and this table are all the same list of numbers
    computed once in `report_query`, so a reader can verify a sentence against a count
    without leaving the page."""
    chart = report_charts.chart_for(result)
    if chart is not None:
        st.altair_chart(chart, width="stretch")

    if result.table:
        st.dataframe(
            pd.DataFrame(result.table),
            width="stretch",
            hide_index=True,
            key=f"table_{key}",
        )
    if result.note:
        st.caption(result.note)


def render_insights(report) -> None:
    """The fixed six-panel dashboard (`report_charts.DASHBOARD_PANELS`). Every number here
    is computed by `report_query` from the findings on disk — no model is involved in this
    tab at all, which is why it renders identically on the read-only deployment."""
    st.markdown("### Biểu đồ tổng hợp")
    st.caption(
        "Mọi con số dưới đây do mã Python đếm trực tiếp từ `report.jsonl`. "
        "Mô hình không tham gia vào tab này."
    )

    columns = st.columns(2)
    for index, (title, op, dimension, help_text) in enumerate(report_charts.DASHBOARD_PANELS):
        spec = report_query.QuerySpec(op=op, dimension=dimension, limit=10)
        try:
            result = report_query.run_query(report, spec)
        except report_query.QuerySpecError as exc:
            columns[index % 2].warning(f"{title}: không dựng được biểu đồ ({exc})")
            continue

        with columns[index % 2].container(border=True):
            st.markdown(f"**{title}**")
            st.caption(help_text)
            render_query_result(result, key=f"panel_{op}_{dimension or 'none'}")


CHAT_HISTORY_KEY = "report_chat_history"
CHAT_PENDING_KEY = "report_chat_pending"
CHAT_ASKED_KEY = "report_chat_asked"

# Per-session ceiling on model-backed questions, on top of the day's token budget in
# `report_chat`. The two guard different things: the token budget bounds the bill, this
# bounds one visitor's share of it so the first person to find the page cannot drink the
# whole day in one sitting. It is deliberately easy to escape — a new session resets it —
# because it is a fairness knob, not an access control. There is no access control here by
# decision (ADR 19); the ceiling that actually protects the wallet is the daily one.
CHAT_MAX_QUESTIONS_PER_SESSION = int(
    os.environ.get("CHAT_MAX_QUESTIONS_PER_SESSION", "").strip() or 25
)

# Which findings the list at the bottom of the Q&A tab is currently scoped to, and the
# question that scoped it. `None` means the whole report.
FOCUS_IDS_KEY = "report_focus_ids"
FOCUS_LABEL_KEY = "report_focus_label"


def focus_findings(finding_ids: list[str], label: str) -> None:
    st.session_state[FOCUS_IDS_KEY] = list(finding_ids)
    st.session_state[FOCUS_LABEL_KEY] = label


def clear_focus() -> None:
    st.session_state[FOCUS_IDS_KEY] = None
    st.session_state[FOCUS_LABEL_KEY] = None


def seed_model_env() -> None:
    """Make `.env` visible to the chat layer on a local checkout, once per process.

    Reuses `bench.parse_env_file` rather than adding a fourth `.env` reader to the repo —
    the same reuse `scripts/analyze.py` makes, and for the same reason. Already-exported
    variables win, so `OPENCODE_BASE_URL=... streamlit run` still overrides the file.

    On the deployed image this is a no-op with nothing to fail into: `.dockerignore`
    excludes `.env`, so the loader finds no file and the chat runs deterministic. That is
    the intended state there, not a degradation to fix."""
    if st.session_state.get("_env_seeded"):
        return
    st.session_state["_env_seeded"] = True
    if scan_runner.runtime_mode() == "readonly":
        return
    try:
        import sys
        from pathlib import Path

        scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
        if str(scripts_dir) not in sys.path:
            sys.path.insert(0, str(scripts_dir))
        import bench as bench_module

        for key, value in bench_module.parse_env_file(bench_module.ENV_FILE).items():
            if value:
                os.environ.setdefault(key, value)
    except Exception:  # noqa: BLE001 — a missing/unreadable .env is a supported state
        return


def _seconds(value: float | None) -> str:
    """A duration a reader can compare at a glance. Sub-second answers are the whole point
    of the prebaked path, so they must not all round to `0s`."""
    if value is None:
        return "—"
    if value < 0.001:
        # Serving from the cache really is this fast. `0 ms` would read as "not measured".
        return "<1 ms"
    if value < 1:
        return f"{value * 1000:.0f} ms"
    return f"{value:.1f} s"


def render_chat_stats(turn) -> None:
    """Model, tokens, wall-clock — under every answer, always the same three facts.

    A prebaked turn reports *both* clocks and says which is which: the milliseconds it took
    to serve, and the seconds the model spent when the prose was written. Collapsing those
    into one number would either hide a real cost or invent a wait that did not happen."""
    if turn.prebaked and turn.model:
        # Two different things a baked turn can be, and they must not read alike: the model
        # wrote these words, or the model only picked the query and a template wrote them.
        wrote = (
            f"mô hình `{turn.model}` viết"
            if turn.baked_answer_source == "llm"
            else f"lời văn từ mẫu — mô hình `{turn.model}` chỉ chọn truy vấn"
        )
        st.caption(
            f":material/bolt: **Trả lời dựng sẵn** · {wrote} · {turn.tokens:,} token · "
            f"{_seconds(turn.elapsed_seconds)} — token và "
            f"{_seconds(turn.baked_elapsed_seconds)} ở trên là chi phí lúc bake, "
            "lần mở trang này không gọi mô hình."
        )
        return
    if turn.prebaked:
        # A cache baked with `--no-llm`. Saying "0 token" beside a model name that was never
        # used would be two half-truths making a whole one; there is no model here at all.
        st.caption(
            f":material/bolt: **Trả lời dựng sẵn** · không dùng mô hình (đường tất định) · "
            f"0 token · {_seconds(turn.elapsed_seconds)}"
        )
        return
    if turn.model:
        st.caption(
            f":material/neurology: mô hình `{turn.model}` · {turn.tokens:,} token · "
            f"{_seconds(turn.elapsed_seconds)}"
        )
        return
    st.caption(
        f":material/function: đường tất định (không gọi mô hình) · 0 token · "
        f"{_seconds(turn.elapsed_seconds)}"
    )


def render_chat_provenance(turn) -> None:
    """How the answer was produced, in the answer's own words. A turn that fell back is
    labelled as one — an answer written by a template must never be mistaken for an answer
    written by the model, and a route the model got wrong has to be diagnosable."""
    route_label = {
        "llm": "mô hình",
        "prebaked": "mô hình, lúc bake",
    }.get(turn.route_source, "từ khoá (tất định)")
    answer_label = {
        "llm": "mô hình",
        "prebaked": (
            "mô hình, lúc bake (lấy từ cache)"
            if turn.baked_answer_source == "llm"
            else "mẫu (tất định) — lúc bake, lời của mô hình đã bị bộ chặn bịa số loại"
        ),
    }.get(turn.answer_source, "mẫu (tất định)")
    with st.expander("Câu trả lời này được tạo ra thế nào?"):
        if turn.prebaked:
            st.markdown(
                f"- **Dựng sẵn lúc:** `{turn.baked_at or '—'}` — lời văn đã có sẵn, "
                "trang không gọi mô hình khi bạn bấm."
            )
            st.markdown(
                "- **Số liệu vẫn tính lại ngay bây giờ:** truy vấn dưới đây chạy lại từ "
                "`report.jsonl` mỗi lần mở trang, và mọi con số trong lời văn được đối "
                "chiếu lại với bảng — không khớp thì cache bị bỏ, không hiện ra."
            )
        st.markdown(
            f"- **Chọn truy vấn:** {route_label}"
            + (f" — mô hình thất bại: `{turn.route_failure}`" if turn.route_failure and turn.route_source == "keyword" else "")
        )
        st.markdown(
            f"- **Viết lời:** {answer_label}"
            + (f" — mô hình bị loại: `{turn.answer_failure}`" if turn.answer_failure and turn.answer_source == "template" else "")
        )
        st.markdown("- **Số liệu:** luôn do `report_query` tính bằng Python, không do mô hình đếm.")
        st.markdown(f"- **Truy vấn đã chạy:** `{turn.spec_json}`")
        st.markdown(
            f"- **Số phát hiện làm căn cứ:** {len(turn.result.finding_ids)} "
            f"(khớp bộ lọc: {turn.result.total})"
        )
        st.markdown(
            f"- **Mô hình:** `{turn.model or 'không dùng mô hình'}` · "
            f"**token:** {turn.tokens:,} · **thời gian:** {_seconds(turn.elapsed_seconds)}"
            + (
                f" (lúc bake: {_seconds(turn.baked_elapsed_seconds)})"
                if turn.prebaked
                else ""
            )
        )
        if turn.prompt_version:
            st.markdown(
                f"- **Prompt:** `{turn.prompt_version}` sha256 `{(turn.prompt_sha256 or '')[:12]}`"
            )
        for note in turn.notes:
            st.caption(note)


def render_chat_turn(turn, index: int, total_findings: int) -> None:
    with st.chat_message("user"):
        st.markdown(turn.question)
    with st.chat_message("assistant"):
        st.markdown(turn.answer)
        render_chat_stats(turn)
        render_query_result(turn.result, key=f"chat_{index}")

        # The bridge into the findings list below. An answer names a subset of the report —
        # `finding_ids` is exactly the evidence it rests on — and until now the only way to
        # read those findings was to leave for another tab and rebuild the filter by hand.
        # This scopes the list in place instead, so the answer and the evidence for it are
        # one surface (DESIGN.md rule 1: tabs are lenses, the reader never navigates out).
        count = len(turn.result.finding_ids)
        focused = st.session_state.get(FOCUS_IDS_KEY) == turn.result.finding_ids
        if count and count < total_findings:
            st.button(
                f"Xem {count} phát hiện làm căn cứ" + (" (đang xem)" if focused else ""),
                key=f"focus_{index}",
                icon=":material/filter_alt:",
                disabled=focused,
                on_click=focus_findings,
                args=(turn.result.finding_ids, turn.question),
            )
        elif count:
            st.caption(
                f"Câu trả lời này dựa trên toàn bộ **{count}** phát hiện — "
                "danh sách đầy đủ nằm ngay dưới."
            )
        render_chat_provenance(turn)


def render_chat_budget_notice() -> None:
    """What the model costs and what is left of today's allowance.

    Shown whenever a real key is present, including locally. A public demo spending real
    money should say so on the page rather than in a README — someone reading an answer has
    a right to know it cost something, and a visitor who finds the budget spent should be
    told that is what happened, not left guessing why the prose went flat."""
    remaining = report_chat.budget_remaining()
    if remaining is None:
        st.caption(
            "Đang dùng **mô hình thật** (2 lần gọi mỗi câu: chọn truy vấn + viết lời). "
            "Không đặt hạn mức token — mọi câu hỏi đều gọi mô hình."
        )
        return

    limit = report_chat.daily_token_budget()
    if remaining <= 0:
        st.info(
            f"**Đã dùng hết hạn mức {limit:,} token của hôm nay.** Câu hỏi vẫn được trả lời "
            "bằng đường tất định (định tuyến từ khoá + mẫu) — **số liệu và biểu đồ không "
            "đổi**, chúng chưa bao giờ do mô hình sinh ra. Hạn mức reset theo ngày UTC.",
            icon=":material/savings:",
        )
        return

    st.caption(
        f"Đang dùng **mô hình thật** (2 lần gọi mỗi câu). Còn **{remaining:,}** / "
        f"{limit:,} token trong hạn mức hôm nay; hết thì tự động lùi về đường tất định "
        "chứ không báo lỗi."
    )


def render_report_chat(report) -> None:
    seed_model_env()
    has_model = report_chat.model_available() and bool(report_chat.default_model())

    st.caption(
        "Hỏi bằng tiếng Việt về chính báo cáo này. Mô hình chỉ chọn truy vấn và viết lời — "
        "mọi con số đều do Python đếm từ `report.jsonl`, và bảng số liệu luôn hiện ngay "
        "dưới câu trả lời để đối chiếu."
    )

    if not has_model:
        # Careful with the wording here: with a baked cache, this instance *does* serve
        # model-written prose for the suggested questions. It just cannot write any new.
        # Saying "no model prose here" flatly would be false on exactly the seven answers
        # most visitors read.
        st.info(
            "**Chế độ không có mô hình.** Bản cài này không có khoá API, nên câu hỏi mới "
            "được định tuyến bằng từ khoá và trả lời bằng mẫu — tất định, không tốn token. "
            "Các **câu hỏi gợi ý** thì đã được trả lời sẵn từ trước bằng mô hình thật, nên "
            "vẫn có lời văn do mô hình viết (kèm số token và thời gian của lần bake đó). "
            "Biểu đồ và số liệu **không đổi** trong mọi trường hợp: chúng chưa bao giờ do "
            "mô hình sinh ra.",
            icon=":material/info:",
        )
    else:
        render_chat_budget_notice()

    history = st.session_state.setdefault(CHAT_HISTORY_KEY, [])

    # The session quota counts questions ASKED, not turns kept, so "Xoá hội thoại" clears
    # the screen without refilling the allowance — otherwise the button would be the bypass.
    asked = st.session_state.get(CHAT_ASKED_KEY, 0)
    out_of_turns = has_model and asked >= CHAT_MAX_QUESTIONS_PER_SESSION
    if out_of_turns:
        st.warning(
            f"Phiên này đã hỏi {asked} câu, chạm hạn mức "
            f"**{CHAT_MAX_QUESTIONS_PER_SESSION}** của một phiên. Đây là bản demo công khai "
            "dùng khoá API thật, nên mỗi phiên có giới hạn. Các câu hỏi tiếp theo vẫn được "
            "trả lời, nhưng bằng **đường tất định** (định tuyến từ khoá + mẫu) — số liệu và "
            "biểu đồ **không đổi**, chỉ lời văn là do mẫu dựng.",
            icon=":material/hourglass_disabled:",
        )

    # The suggested questions are baked (`scripts/bake_chat.py`), so they answer in
    # milliseconds. Saying so on the buttons is not decoration: it tells a reader which
    # click is free and instant and which one will make them wait for two model calls.
    baked = report_chat.prebaked_questions()
    if not history:
        st.markdown("**Thử một câu hỏi:**")
        if baked:
            st.caption(
                ":material/bolt: Các câu hỏi gợi ý đã được trả lời sẵn — bấm là hiện ngay, "
                "không phải đợi mô hình."
            )
        suggestion_columns = st.columns(3)
        for index, suggestion in enumerate(report_chat.SUGGESTED_QUESTIONS):
            is_baked = report_chat.is_prebaked(suggestion, baked)
            if suggestion_columns[index % 3].button(
                suggestion,
                key=f"suggest_{index}",
                width="stretch",
                icon=":material/bolt:" if is_baked else None,
            ):
                st.session_state[CHAT_PENDING_KEY] = suggestion
                st.rerun()

    total_findings = len(report.findings)
    for index, turn in enumerate(history):
        render_chat_turn(turn, index, total_findings)

    question = st.session_state.pop(CHAT_PENDING_KEY, None) or st.chat_input(
        "ví dụ: lỗi CWE-89 nằm ở những tệp nào?"
    )
    if question:
        # Tried first, and for any question — a visitor who retypes a suggested question
        # deserves the same instant answer the button gives. A miss costs one small file
        # read and falls straight through to the path that was always here.
        turn = report_chat.prebaked_answer(question, report)
        if turn is None:
            with st.spinner("Đang tra báo cáo…"):
                turn = report_chat.answer(
                    question, report, use_llm=has_model and not out_of_turns
                )
            # A prebaked answer spends nothing, so it does not draw down the session's share
            # of the budget either. The quota exists to bound model calls, not clicks.
            st.session_state[CHAT_ASKED_KEY] = asked + 1
        history.append(turn)
        focus_findings(turn.result.finding_ids, turn.question)
        st.rerun()

    if history and st.button("Xoá hội thoại", icon=":material/delete:"):
        st.session_state[CHAT_HISTORY_KEY] = []
        clear_focus()
        st.rerun()


def page_security_report() -> None:
    st.title("Security Report")
    st.caption(
        "Cảnh báo từ các lần quét, gộp nhóm và giải thích bằng tiếng Việt. "
        "Trang này chỉ đọc một báo cáo đã được sinh sẵn."
    )

    try:
        report = security_agent.load_report()
    except security_agent.ReportCorruptError as exc:
        st.error(f"Báo cáo hỏng, không đọc được: {exc}", icon=":material/error:")
        return

    if report is None:
        st.info("Chưa có báo cáo nào được sinh trên bản cài này.", icon=":material/info:")
        with st.container(border=True):
            st.markdown("Sinh báo cáo bằng lệnh sau trong một bản checkout có khoá API:")
            st.code("./scripts/analyze.py", language="bash")
            st.caption(
                "Bản triển khai công khai không giữ khoá mô hình nên không thể tự sinh "
                "báo cáo, đúng như nó không thể tự chạy quét."
            )
        return

    meta = report.meta
    render_report_status_banner(meta)

    # Hỏi đáp first, and therefore selected on open. The findings list is no longer a tab
    # of its own: a list of 93 findings is not a third thing to look at, it is the evidence
    # under whatever was just asked, so it now lives at the bottom of Hỏi đáp where an
    # answer can scope it.
    chat_tab, overview_tab = st.tabs(["Hỏi đáp", "Tổng quan"])

    with chat_tab:
        render_report_chat(report)
        st.divider()
        render_findings_list(report, meta)

    with overview_tab:
        render_report_kpis(report)
        st.divider()
        render_severity_confidence_matrix(report)
        st.divider()
        render_insights(report)


def render_findings_list(report, meta) -> None:
    st.subheader("Danh sách phát hiện")

    # Two scopes, stacked and both visible: what the last answer rests on, then the manual
    # filters on top of it. Keeping the answer's scope as a dismissable banner rather than
    # folding it into the filter widgets means the reader can always see *why* they are
    # looking at 12 findings instead of 93, and undo it in one click.
    findings = report.findings
    focus_ids = st.session_state.get(FOCUS_IDS_KEY)
    if focus_ids is not None and len(focus_ids) < len(report.findings):
        wanted = set(focus_ids)
        findings = [f for f in report.findings if f.finding_id in wanted]
        label = st.session_state.get(FOCUS_LABEL_KEY) or "câu hỏi vừa rồi"
        banner, action = st.columns([4, 1], vertical_alignment="center")
        banner.info(
            f"Đang thu hẹp theo câu trả lời cho **“{label}”** — "
            f"{len(findings)}/{len(report.findings)} phát hiện.",
            icon=":material/filter_alt:",
        )
        action.button(
            "Xem tất cả",
            width="stretch",
            icon=":material/filter_alt_off:",
            on_click=clear_focus,
        )

    with st.container(border=True):
        filter_columns = st.columns([1, 1, 2])
        with filter_columns[0]:
            severities = st.multiselect("Mức độ", SEVERITY_ORDER, key="report_severities")
        with filter_columns[1]:
            confidences = st.multiselect("Tin cậy", CONFIDENCE_ORDER, key="report_confidences")
        with filter_columns[2]:
            query = st.text_input(
                "Tìm theo tiêu đề, CWE hoặc tên tệp",
                placeholder="ví dụ: SQL, CWE-330, BenchmarkTest00024.java",
                key="report_query",
            )

    visible = filter_findings(findings, severities, confidences, query)
    st.markdown(f"Đang hiện **{len(visible)}** trên tổng số **{len(report.findings)}** phát hiện.")

    if not visible:
        st.info("Không có phát hiện nào khớp bộ lọc hiện tại.", icon=":material/filter_alt:")
    for finding in visible:
        header = (
            f"{finding.title} · {finding.severity} · "
            f"{finding.evidence.occurrence_count} lần xuất hiện"
        )
        with st.expander(header):
            badge = severity_badge(finding.severity)
            if finding.severity_clamped:
                badge += (
                    f' &nbsp;<span style="font-size:0.85em">công cụ báo '
                    f"<code>{finding.severity_source}</code>, báo cáo hạ/nâng thành "
                    f"<code>{finding.severity}</code></span>"
                )
            else:
                badge += (
                    f' &nbsp;<span style="font-size:0.85em">công cụ cũng báo '
                    f"<code>{finding.severity_source}</code></span>"
                )
            st.markdown(badge, unsafe_allow_html=True)
            if finding.severity_rationale:
                st.caption(finding.severity_rationale)
            st.markdown(f"`{finding.cwe or 'CWE không xác định'}` · `{finding.finding_id}`")
            render_finding_body(finding)

    st.divider()
    st.download_button(
        "Tải báo cáo JSONL",
        data=findings_as_jsonl(report.findings).encode("utf-8"),
        file_name=security_agent.REPORT_FILENAME,
        mime="application/x-ndjson",
        icon=":material/download:",
    )
    st.caption(
        f"Sinh lúc {meta.generated_at} · nguồn `{meta.input_source}` · "
        f"mô hình `{meta.model or 'không dùng mô hình'}` · "
        f"prompt `{meta.prompt_version}` sha256 `{(meta.prompt_sha256 or '—')[:12]}`"
    )


st.set_page_config(page_title="Scan BenchmarkJava", page_icon=":material/security:", layout="wide")
st.html(PAGE_CSS)

is_readonly = scan_runner.runtime_mode() == "readonly"

st.sidebar.markdown("### :material/security: Scan BenchmarkJava")
st.sidebar.caption("Metis vs OWASP BenchmarkJava")

# A read-only instance does not build the Run Scan page at all. Its entire content there
# was a notice explaining that scanning is unavailable, and a nav entry whose only job is
# to apologise is worse than no entry — the deploy now shows only what it can actually
# serve. This is presentation, not protection: what makes the instance safe is still
# `scan_runner`'s own refusal to spawn (ADR 19), which is why `page_run_scan` keeps its
# read-only guard even though nothing can reach it here.
#
# Security Report is the landing page in BOTH modes now. That is a deliberate trade with a
# cost worth naming: Streamlit serves the default page at `/` and IGNORES its `url_path`
# (`navigation/page.py`: `return "" if self._default else self._url_path`), so making this
# page the default is exactly what makes `/security-report` stop resolving. The published
# deep link moves to the site root, which is the URL that now shows the report — README,
# the week-3 report and the e2e probe were updated together with this line, and nothing
# published points at `/comparison` or `/run`.
security_page = st.Page(page_security_report, title="Security Report",
                        icon=":material/shield:", url_path="security-report", default=True)
pages = [
    security_page,
    st.Page(page_results, title="Comparison", icon=":material/bar_chart:",
            url_path="comparison"),
    st.Page(page_knowledge_base, title="Knowledge Base", icon=":material/search:",
            url_path="knowledge-base"),
]
if not is_readonly:
    # Local only, and last: it is the one page the deploy cannot serve, so it does not get
    # to displace the page every visitor comes for.
    pages.append(st.Page(page_run_scan, title="Run Scan", icon=":material/play_circle:",
                         url_path="run"))
current_page = st.navigation(pages)

with st.sidebar:
    st.divider()
    if is_readonly:
        st.caption("Read-only instance")
        st.markdown(":material/lock: **Scans disabled**")
    else:
        st.caption("Active run")
        render_active_run_badge()

current_page.run()
