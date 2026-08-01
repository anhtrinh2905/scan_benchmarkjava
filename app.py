"""Streamlit control panel for the Metis/BenchmarkJava scan harness.

Run config (C-002), background execution (C-003), and results viewer (C-004) below.
UI reorganized into a sidebar-navigated, multipage layout (Run Scan / Results /
Knowledge Base) — all `scan_runner`/`kb_search` calls and their contracts are
unchanged; this is a presentation-layer restructure only.

C-012 added the deploy surface: a read-only Run Scan page, backed by `scan_runner`'s own
refusal to spawn. C-013 removed the password gate that shipped alongside it — the
deployed instance is public by decision (ADR 19); what keeps it safe is that it cannot
act, not that it is hard to reach.
"""
import shlex

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


@st.fragment(run_every=1)
def render_run_progress(handle: scan_runner.RunHandle) -> None:
    status = scan_runner.poll_run(handle)
    label = STATUS_LABEL[status.state]
    if status.returncode is not None:
        label += f" (exit code {status.returncode})"
    with st.status(label, state=STATUS_STATE[status.state], expanded=status.state != "done"):
        st.code(status.log_tail or "(no output yet)", language=None)


@st.fragment(run_every=1)
def render_active_run_badge() -> None:
    handle = st.session_state.get("run_handle")
    if handle is None:
        st.caption("No active run")
        return
    status = scan_runner.poll_run(handle)
    st.markdown(f"{STATUS_ICON[status.state]} **{STATUS_LABEL[status.state]}**")
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


def page_results() -> None:
    st.title("Results")
    st.caption("Browse scorecards and comparison tables from past runs.")

    kind = st.segmented_control(
        "Scan type", options=["bench", "sweep", "ablation"], default="bench", key="results_kind"
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

    with st.container(border=True):
        st.markdown(bundle.scorecard_md or "_(no scorecard found for this run)_")

    if bundle.compare_rows is not None:
        st.subheader("Comparison")
        st.dataframe(bundle.compare_rows)


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


def render_kb_category(label: str, hits: list, category: str) -> None:
    items = [hit for hit in hits if hit.category == category]
    st.markdown(f"**{label}** · `{len(items)}`")
    if not items:
        st.caption("No matches in this category above the current threshold.")
        return
    for hit in items:
        render_kb_hit(hit)


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
    if search_clicked and kb_query:
        st.session_state.kb_active_query = kb_query
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

    examples_col, side_col = st.columns([2, 1])
    with examples_col:
        render_kb_category("examples", hits, "examples")
    with side_col:
        render_kb_category("owasp-top10", hits, "owasp-top10")
        st.markdown("")
        render_kb_category("rules", hits, "rules")


st.set_page_config(page_title="Scan BenchmarkJava", page_icon=":material/security:", layout="wide")

is_readonly = scan_runner.runtime_mode() == "readonly"

st.sidebar.markdown("### :material/security: Scan BenchmarkJava")
st.sidebar.caption("Metis vs OWASP BenchmarkJava")

# A read-only instance lands on Results — the page it can actually serve — rather than
# on a Run Scan page whose only content is why it is unavailable.
pages = [
    st.Page(page_run_scan, title="Run Scan", icon=":material/play_circle:", url_path="run",
            default=not is_readonly),
    st.Page(page_results, title="Results", icon=":material/bar_chart:", url_path="results",
            default=is_readonly),
    st.Page(page_knowledge_base, title="Knowledge Base", icon=":material/search:", url_path="knowledge-base"),
]
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
