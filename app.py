"""Streamlit control panel for the Metis/BenchmarkJava scan harness.

Run config (C-002), background execution (C-003), and results viewer (C-004) below.
UI reorganized into a sidebar-navigated, multipage layout (Run Scan / Results /
Knowledge Base) — all `scan_runner`/`kb_search` calls and their contracts are
unchanged; this is a presentation-layer restructure only.
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
    st.title("Run Scan")
    st.caption("Configure, review, and launch a Metis vs OWASP BenchmarkJava scan.")

    with st.container(border=True):
        st.subheader("Configuration")
        left, right = st.columns(2)
        with left:
            kind = st.selectbox("Scan type", options=["bench", "sweep", "ablation"], key="run_kind")
            sample = st.slider("Sample size", min_value=1, max_value=2740, value=100, key="run_sample")
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

    if search_clicked and kb_query:
        hits = search_kb(kb_query, mode=kb_mode)
        if not hits:
            st.info("No matching KB docs found.", icon=":material/info:")
        else:
            for hit in hits:
                with st.container(border=True):
                    title_col, score_col = st.columns([4, 1])
                    title_col.markdown(f"**{hit.title}**  \n`{hit.doc_id}`")
                    score_col.metric("Score", f"{hit.score:.2f}")
                    st.caption(hit.snippet)


st.set_page_config(page_title="Scan BenchmarkJava", page_icon=":material/security:", layout="wide")

st.sidebar.markdown("### :material/security: Scan BenchmarkJava")
st.sidebar.caption("Metis vs OWASP BenchmarkJava")

pages = [
    st.Page(page_run_scan, title="Run Scan", icon=":material/play_circle:", url_path="run", default=True),
    st.Page(page_results, title="Results", icon=":material/bar_chart:", url_path="results"),
    st.Page(page_knowledge_base, title="Knowledge Base", icon=":material/search:", url_path="knowledge-base"),
]
current_page = st.navigation(pages)

with st.sidebar:
    st.divider()
    st.caption("Active run")
    render_active_run_badge()

current_page.run()
