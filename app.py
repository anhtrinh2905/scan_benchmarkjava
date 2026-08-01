"""Streamlit control panel for the Metis/BenchmarkJava scan harness.

Run config (C-002), background execution (C-003), and results viewer (C-004) below.
UI reorganized into a sidebar-navigated, multipage layout (Run Scan / Results / Matrix /
Knowledge Base) — all `scan_runner`/`kb_search` calls and their contracts are
unchanged; this is a presentation-layer restructure only.

C-012 added the deploy surface: a read-only Run Scan page, backed by `scan_runner`'s own
refusal to spawn. C-013 removed the password gate that shipped alongside it — the
deployed instance is public by decision (ADR 19); what keeps it safe is that it cannot
act, not that it is hard to reach.

C-014 (v1.5) added the Matrix page — one cross-run table, 100 test files by 15 runs
(FR14) — and rebuilt Results as a metrics-first grid (FR15). Both read only through the
`scan_runner` seam: this file opens no file under `results/` and parses no run JSON.
"""
import shlex

import pandas as pd
import streamlit as st

import scan_runner
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

# The outcome-status scale, declared once in DESIGN.md (2026-08-01). Colour is
# reinforcement only — every cell that gets a tint also prints its literal outcome text,
# so the table survives colourblindness, greyscale, and the CSV export (ADR 22).
OUTCOME_STYLE = {
    "TP": "background-color:#ECFDF5;color:#065F46;font-weight:600",
    "TN": "background-color:#F0FDFA;color:#115E59",
    "FN": "background-color:#FEF2F2;color:#991B1B;font-weight:600",
    "FP": "background-color:#FFF7ED;color:#9A3412;font-weight:600",
}
OUTCOME_MEANING = {
    "TP": "caught a real vulnerability",
    "TN": "correctly left a safe file alone",
    "FN": "missed a real vulnerability",
    "FP": "false alarm on a safe file",
}


def render_readonly_run_notice() -> None:
    st.title("Run Scan")
    st.caption("Not available on this instance.")
    with st.container(border=True):
        st.markdown(
            "This is a shared, read-only copy of the control panel. It holds no model "
            "credentials and cannot start a scan, so nothing here can spend LLM budget."
        )
        st.markdown(
            "**Results** and **Knowledge Base** show real output from scans already run. "
            "To run a new scan, use a local checkout:"
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
    # The badge is on every page, so a run stays watchable while reading Results or
    # Matrix — the same counted numbers, no second source of truth.
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
    st.title("Results")
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
    st.caption("To see this run beside every other one, per test file, open **Matrix**.")

    if bundle.compare_rows is not None:
        st.subheader("Comparison")
        st.caption(
            f"The same batch as a sortable table — one row per {KIND_UNIT[kind]}, "
            "not per test file."
        )
        frame, column_config = compare_table(bundle.compare_rows)
        st.dataframe(frame, column_config=column_config, hide_index=True, width="stretch")


@st.cache_data(show_spinner="Reading run artifacts…")
def cached_matrix() -> scan_runner.Matrix:
    """One parse of all 15 run artifacts per server process. The matrix is derived on
    read and never persisted (ADR 21); this cache is what keeps that cheap across the
    reruns every filter widget triggers."""
    return scan_runner.load_matrix()


def render_matrix_pulse(matrix: scan_runner.Matrix, view: scan_runner.Matrix) -> None:
    """At-a-glance shape of the table, before the controls that change it. Each number
    is `shown / total` so a filter never hides the fact that it is hiding something."""
    always_wrong = sum(1 for row in view.rows if row.covered and row.detected == 0)
    strip = st.columns(4)
    strip[0].metric("Test files", f"{len(view.rows)} / {len(matrix.rows)}", border=True)
    strip[1].metric("Scan runs", f"{len(view.runs)} / {len(matrix.runs)}", border=True)
    strip[2].metric(
        "Scored cells", f"{view.total_cells:,} / {matrix.total_cells:,}", border=True
    )
    strip[3].metric(
        "Never right", always_wrong,
        help="Files that every shown run which scanned them got wrong — the hard cases.",
        border=True,
    )


def render_outcome_legend() -> None:
    st.caption(
        "  ·  ".join(f"**{code}** {meaning}" for code, meaning in OUTCOME_MEANING.items())
        + "  ·  **blank** this run never scanned this file"
    )


MATRIX_FILTER_DEFAULTS = {
    "matrix_query": "",
    "matrix_scoring": "strict",
    "matrix_categories": [],
    "matrix_kinds": [],
    "matrix_run_labels": [],
    "matrix_outcomes": [],
    "matrix_only_disputed": False,
}

# Column headers carry the scan type because `baseline` exists as BOTH a bench tag and a
# sweep variant — two adjacent columns headed `baseline` is exactly the ambiguity a
# comparison table exists to remove. "ablation" is abbreviated so the prefix does not eat
# the whole visible width; the full label is in every column's tooltip.
KIND_PREFIX = {"bench": "bench", "sweep": "sweep", "ablation": "abl"}


def column_header(ref: scan_runner.RunRef) -> str:
    return f"{KIND_PREFIX[ref.kind]}·{ref.name}"


def current_matrix_filters() -> dict:
    """The filter values in force for THIS run, read from the widgets' own session-state
    keys rather than from `matrix_filter_bar`'s return value.

    Streamlit refreshes a keyed widget's session-state entry before the rerun its change
    triggered, so reading here lets the pulse strip and the coverage note render ABOVE
    the filter bar while still reflecting the current selection. Taking the bar's return
    value instead would leave the count one interaction behind the table."""
    return {
        name.removeprefix("matrix_"): st.session_state.get(name, default)
        for name, default in MATRIX_FILTER_DEFAULTS.items()
    }


def matrix_filter_bar(matrix: scan_runner.Matrix) -> None:
    """Every FR14 facet in one bordered block. The widgets write to session_state under
    the keys `current_matrix_filters` reads; `scan_runner.filter_matrix` does the actual
    narrowing, so what the user sees is produced by the same pure function a test calls."""
    with st.container(border=True):
        search_col, scoring_col = st.columns([2.5, 1])
        with search_col:
            st.text_input(
                "Search",
                placeholder="Test id, category, or CWE — e.g. 00042, sqli, cwe-89",
                key="matrix_query",
                label_visibility="collapsed",
            )
        with scoring_col:
            st.segmented_control(
                "Scoring",
                options=["strict", "lenient"],
                default="strict",
                key="matrix_scoring",
                help="strict counts an inconclusive triage as still-reported; "
                     "lenient counts it as dismissed.",
            )

        cat_col, kind_col, outcome_col = st.columns(3)
        with cat_col:
            st.multiselect(
                "Category",
                options=scan_runner.matrix_categories(matrix),
                key="matrix_categories",
                placeholder="All categories",
            )
        with kind_col:
            st.multiselect(
                "Scan type",
                options=["bench", "sweep", "ablation"],
                format_func=lambda k: KIND_LABEL[k],
                key="matrix_kinds",
                placeholder="All scan types",
                help="Selects which run COLUMNS the table shows.",
            )
        with outcome_col:
            st.multiselect(
                "Outcome",
                options=list(OUTCOME_MEANING),
                format_func=lambda code: f"{code} — {OUTCOME_MEANING[code]}",
                key="matrix_outcomes",
                placeholder="Any outcome",
                help="Keeps files where at least one shown run scored this way.",
            )

        # 15 columns do not fit one screen. Naming two or three runs here is how the
        # matrix becomes a head-to-head comparison instead of a wide scroll.
        st.multiselect(
            "Runs",
            options=[ref.label for ref in matrix.runs],
            key="matrix_run_labels",
            placeholder="All runs — or name two or three to compare them side by side",
        )
        st.toggle(
            "Only files the runs disagree about",
            key="matrix_only_disputed",
            help="Hides files every shown run scored the same way, leaving the ones "
                 "where configuration actually changed the answer.",
        )


def render_matrix_table(matrix: scan_runner.Matrix, strict: bool) -> pd.DataFrame:
    """The one table FR14 asks for: rows are test files, columns are runs. Returns the
    frame so the caller can offer exactly what is on screen as a CSV."""
    frame = pd.DataFrame(scan_runner.matrix_records(matrix, strict=strict))
    run_labels = [ref.label for ref in matrix.runs]

    styled = frame.style.map(
        lambda value: OUTCOME_STYLE.get(value, ""), subset=run_labels
    )
    column_config = {
        "test": st.column_config.TextColumn("Test file", pinned=True, width="medium"),
        "category": st.column_config.TextColumn("Category", width="small"),
        "cwe": st.column_config.TextColumn("CWE", width="small"),
        "expected": st.column_config.TextColumn("Truth", width="small"),
        "covered": st.column_config.NumberColumn(
            "Runs", help="How many runs scanned this file.", width="small"
        ),
        "detected": st.column_config.NumberColumn(
            "Right", help="How many of those runs scored it correctly.", width="small"
        ),
        "detection_rate": st.column_config.ProgressColumn(
            "Hit rate", min_value=0.0, max_value=1.0, format="percent", width="small"
        ),
    }
    for ref in matrix.runs:
        column_config[ref.label] = st.column_config.TextColumn(
            column_header(ref),
            width="small",
            help=f"{KIND_LABEL[ref.kind]} run `{ref.name}` — scanned {ref.test_count} "
                 f"test files in total.",
        )

    # Grow to fit, cap at ~14 rows. A fixed height leaves a filtered-down table of four
    # rows sitting in half a screen of empty grid, which reads as "still loading".
    st.dataframe(
        styled,
        column_config=column_config,
        hide_index=True,
        height=min(560, 45 + 35 * len(frame)),
        width="stretch",
    )
    return frame


def page_matrix() -> None:
    st.title("Matrix")
    st.caption(
        "Every test file against every scan run, in one table — so a file no "
        "configuration ever gets right is visible at a glance."
    )

    matrix = cached_matrix()
    if not matrix.runs:
        st.info(
            "No runs on disk carry per-test results yet — start one from **Run Scan**.",
            icon=":material/info:",
        )
        return

    # Pulse strip first, then the controls that change it (DESIGN.md object page pattern):
    # the shape of the data is what the page is about; the filters are how you narrow it.
    # `shown` is resolved before rendering so the count and the table can never disagree.
    filters = current_matrix_filters()
    view = scan_runner.filter_matrix(
        matrix,
        query=filters["query"],
        categories=filters["categories"] or None,
        kinds=filters["kinds"] or None,
        run_labels=filters["run_labels"] or None,
        outcomes=filters["outcomes"] or None,
        only_disputed=filters["only_disputed"],
    )
    render_matrix_pulse(matrix, view)

    # Blank and missed are different facts, and at these coverage spreads (6 to 100
    # files) confusing them turns a smoke run into 94 imaginary misses. The page says so
    # in words rather than trusting the reader to infer it (ADR 22).
    coverage_note = view.coverage_note or matrix.coverage_note
    if coverage_note:
        st.info(coverage_note, icon=":material/info:")

    matrix_filter_bar(matrix)

    if not view.rows:
        st.warning(
            "No test file matches all of these filters at once. Try clearing **Outcome** "
            "first — it is the narrowest facet, and an outcome only exists on runs that "
            "actually scanned the file. If you also narrowed **Runs** or **Scan type**, "
            "widen those next: they hide columns, so they can empty a row entirely.",
            icon=":material/search_off:",
        )
        return

    render_outcome_legend()
    frame = render_matrix_table(view, strict=filters["scoring"] == "strict")

    export_col, note_col = st.columns([1, 3])
    with export_col:
        st.download_button(
            "Download this view",
            data=frame.to_csv(index=False).encode("utf-8"),
            file_name=f"matrix-{filters['scoring']}-{len(view.rows)}-files.csv",
            mime="text/csv",
            icon=":material/download:",
            width="stretch",
        )
    with note_col:
        st.caption(
            f"Exports the {len(view.rows)} row(s) and {len(view.runs)} run column(s) "
            "currently on screen, scored **"
            f"{filters['scoring']}** — not the unfiltered table."
        )


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


st.set_page_config(page_title="Scan BenchmarkJava", page_icon=":material/security:", layout="wide")
st.html(PAGE_CSS)

is_readonly = scan_runner.runtime_mode() == "readonly"

st.sidebar.markdown("### :material/security: Scan BenchmarkJava")
st.sidebar.caption("Metis vs OWASP BenchmarkJava")

# Streamlit serves the default page at `/` and IGNORES its `url_path`, so exactly one
# page can never be linked to by name — asking for it opened a "Page not found" dialog.
# Making `default` mode-dependent made that worse: the dead link was `/run` locally but
# `/results` on the deploy, so the most shareable URL of the read-only instance was the
# one that 404'd. Run Scan is the default on both instances now and answers to `/` (no
# `url_path`, because it would be a promise Streamlit does not keep); Results, Matrix and
# Knowledge Base each keep a URL that resolves everywhere (nav: deep-linking).
run_page = st.Page(page_run_scan, title="Run Scan", icon=":material/play_circle:",
                   default=True)
results_page = st.Page(page_results, title="Results", icon=":material/bar_chart:",
                       url_path="results")
pages = [
    run_page,
    results_page,
    st.Page(page_matrix, title="Matrix", icon=":material/grid_on:", url_path="matrix"),
    st.Page(page_knowledge_base, title="Knowledge Base", icon=":material/search:", url_path="knowledge-base"),
]
current_page = st.navigation(pages)

# A read-only instance still LANDS on Results — the page it can actually serve — rather
# than on a Run Scan page whose only content is why it is unavailable. Once per session,
# and only for someone who arrived at `/`: a deep link to any page is left alone.
if is_readonly and current_page == run_page and not st.session_state.get("landed"):
    st.session_state.landed = True
    st.switch_page(results_page)

with st.sidebar:
    st.divider()
    if is_readonly:
        st.caption("Read-only instance")
        st.markdown(":material/lock: **Scans disabled**")
    else:
        st.caption("Active run")
        render_active_run_badge()

current_page.run()
