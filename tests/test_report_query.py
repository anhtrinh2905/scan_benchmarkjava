"""C-021 — the report query layer, the chart specs, and the hybrid chat.

Offline by construction, same discipline as `test_security_agent.py`: the `_offline`
autouse fixture replaces `requests.post` with a raiser, so this suite makes **zero** real
API calls. A test that wants to exercise the model path stubs `report_chat._post_chat`
explicitly and is therefore visible as such.

The properties under test are the three this stack advertises:

* the model never counts — `test_narration_carrying_an_invented_number_is_rejected`
* conservation — `test_count_by_conserves_every_finding_on_every_dimension`
* every failure degrades to a labelled deterministic answer, never to an error page
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import report_charts  # noqa: E402
import report_chat  # noqa: E402
import report_query as rq  # noqa: E402
import security_agent as agent  # noqa: E402

REAL_REPORT_DIR = ROOT / "data" / "analysis"


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """No test in this file is allowed to reach the network."""

    def forbidden(*args, **kwargs):
        raise AssertionError("a test tried to make a real HTTP call")

    monkeypatch.setattr("requests.post", forbidden)


@pytest.fixture(autouse=True)
def _fresh_budget():
    """The chat's token ledger is process-global, so without this a test that spends tokens
    leaks into the next one — and eventually into a false 'budget exhausted'."""
    report_chat.reset_budget()
    yield
    report_chat.reset_budget()


@pytest.fixture(scope="module")
def report():
    """The report committed to the repo — the same bytes the deployed page serves, so the
    numbers asserted here are the numbers a reader sees."""
    loaded = agent.load_report(REAL_REPORT_DIR)
    assert loaded is not None, "data/analysis/report.jsonl is missing"
    return loaded


def _finding(report, **overrides):
    return report.findings[0]


# --- specs ------------------------------------------------------------------------


def test_validate_spec_rejects_an_operation_outside_the_closed_set():
    with pytest.raises(rq.QuerySpecError, match="thao tác không hợp lệ"):
        rq.validate_spec(rq.QuerySpec(op="drop_table"))


def test_validate_spec_rejects_a_dimension_outside_the_closed_set():
    with pytest.raises(rq.QuerySpecError, match="chiều thống kê không hợp lệ"):
        rq.validate_spec(rq.QuerySpec(op="count_by", dimension="password"))


def test_count_by_without_a_dimension_is_an_error_not_a_silent_default():
    with pytest.raises(rq.QuerySpecError, match="cần một chiều"):
        rq.validate_spec(rq.QuerySpec(op="count_by"))


def test_validate_spec_rejects_an_unknown_filter_key_rather_than_ignoring_it():
    # A filter that silently does nothing is worse than one that is refused: the count
    # still looks authoritative while answering a different question.
    with pytest.raises(rq.QuerySpecError, match="bộ lọc không hợp lệ"):
        rq.validate_spec(rq.QuerySpec(op="list_findings", filters={"secret": "x"}))


def test_a_dimension_is_dropped_for_every_op_that_is_not_count_by():
    spec = rq.validate_spec(rq.QuerySpec(op="top_files", dimension="severity"))
    assert spec.dimension is None


@pytest.mark.parametrize("limit,expected", [(-5, 1), (0, 1), (7, 7), (10_000, rq.MAX_LIMIT)])
def test_limit_is_clamped_into_range(limit, expected):
    assert rq.validate_spec(rq.QuerySpec(op="list_findings", limit=limit)).limit == expected


def test_spec_from_dict_rejects_extra_keys_a_model_might_invent():
    with pytest.raises(rq.QuerySpecError, match="khoá thừa"):
        rq.spec_from_dict({"op": "overview", "sql": "select 1"})


def test_spec_from_dict_rejects_a_non_object():
    with pytest.raises(rq.QuerySpecError, match="đối tượng JSON"):
        rq.spec_from_dict(["overview"])


def test_spec_from_dict_rejects_a_non_integer_limit():
    with pytest.raises(rq.QuerySpecError, match="limit"):
        rq.spec_from_dict({"op": "overview", "limit": "nhiều"})


def test_spec_from_dict_accepts_the_shape_the_prompt_documents():
    spec = rq.spec_from_dict(
        {"op": "count_by", "dimension": "severity", "filters": {"tool": "metis"}, "limit": 5}
    )
    assert (spec.op, spec.dimension, spec.filters, spec.limit) == (
        "count_by",
        "severity",
        {"tool": "metis"},
        5,
    )


# --- conservation -----------------------------------------------------------------


@pytest.mark.parametrize("dimension", rq.DIMENSIONS)
def test_count_by_conserves_every_finding_on_every_dimension(report, dimension):
    """The guarantee a chart leans on: the bars add up to the total printed beside them.
    A finding whose value is missing counts under `UNKNOWN_LABEL` rather than vanishing."""
    result = rq.run_query(report, rq.QuerySpec(op="count_by", dimension=dimension))
    assert sum(row["count"] for row in result.table) == result.total
    assert result.total == len(report.findings)


def test_a_finding_with_no_cwe_is_labelled_not_dropped(report):
    result = rq.run_query(report, rq.QuerySpec(op="count_by", dimension="owasp"))
    labels = {row["label"] for row in result.table}
    # The shipped report has 24 findings with no OWASP category; the chart must show that
    # gap rather than quietly shrinking the denominator.
    assert rq.UNKNOWN_LABEL in labels
    assert sum(row["count"] for row in result.table) == len(report.findings)


def test_ordinal_dimensions_keep_scale_order_and_show_empty_levels(report):
    result = rq.run_query(report, rq.QuerySpec(op="count_by", dimension="severity"))
    assert [row["label"] for row in result.table] == list(rq.SEVERITY_ORDER)


def test_nominal_dimensions_are_sorted_by_count_descending(report):
    result = rq.run_query(report, rq.QuerySpec(op="count_by", dimension="cwe"))
    counts = [row["count"] for row in result.table]
    assert counts == sorted(counts, reverse=True)


def test_every_result_carries_the_findings_it_rests_on(report):
    for op in ("overview", "top_files", "kb_coverage"):
        result = rq.run_query(report, rq.QuerySpec(op=op))
        assert len(result.finding_ids) == len(report.findings)


# --- filters ----------------------------------------------------------------------


def test_a_severity_filter_narrows_the_denominator(report):
    result = rq.run_query(
        report, rq.QuerySpec(op="list_findings", filters={"severity": "critical"}, limit=100)
    )
    assert result.total > 0
    assert all(row["severity"] == "critical" for row in result.table)


def test_a_cwe_filter_matches_case_insensitively(report):
    lower = rq.apply_filters(report.findings, {"cwe": "cwe-89"})
    upper = rq.apply_filters(report.findings, {"cwe": "CWE-89"})
    assert lower and [f.finding_id for f in lower] == [f.finding_id for f in upper]


def test_a_file_filter_matches_a_path_fragment(report):
    kept = rq.apply_filters(report.findings, {"file": "BenchmarkTest00024"})
    assert kept
    assert all(
        any("BenchmarkTest00024" in location.file for location in f.locations) for f in kept
    )


def test_a_filter_that_matches_nothing_yields_zero_not_an_error(report):
    result = rq.run_query(report, rq.QuerySpec(op="list_findings", filters={"cwe": "CWE-99999"}))
    assert result.total == 0
    assert result.table == []


def test_the_empty_answer_says_no_match_and_not_no_vulnerabilities(report):
    """The same distinction `status == "empty"` makes in the report itself. An empty
    filter result must never read as a clean bill of health."""
    result = rq.run_query(report, rq.QuerySpec(op="list_findings", filters={"cwe": "CWE-99999"}))
    text = rq.template_answer(result)
    assert "không phải" in text and "không có lỗ hổng" in text


# --- operations -------------------------------------------------------------------


def test_top_files_ranks_by_distinct_findings_and_respects_the_limit(report):
    result = rq.run_query(report, rq.QuerySpec(op="top_files", limit=5))
    assert len(result.table) == 5
    counts = [row["count"] for row in result.table]
    assert counts == sorted(counts, reverse=True)


def test_list_findings_is_ordered_severity_first(report):
    result = rq.run_query(report, rq.QuerySpec(op="list_findings", limit=20))
    ranks = [rq.SEVERITY_ORDER.index(row["severity"]) for row in result.table]
    assert ranks == sorted(ranks)


def test_list_findings_says_how_many_it_did_not_show(report):
    result = rq.run_query(report, rq.QuerySpec(op="list_findings", limit=3))
    assert len(result.table) == 3
    assert result.total == len(report.findings)
    assert result.note and "không hiện ở đây" in result.note


def test_lookup_returns_one_finding_with_its_full_prose(report):
    target = report.findings[0]
    result = rq.run_query(report, rq.QuerySpec(op="lookup", filters={"text": target.finding_id}))
    assert len(result.table) == 1
    assert result.table[0]["finding_id"] == target.finding_id
    assert result.table[0]["explanation"] == target.explanation


def test_kb_coverage_counts_cited_and_uncited_and_they_add_up(report):
    result = rq.run_query(report, rq.QuerySpec(op="kb_coverage"))
    cited, uncited = result.table[0]["count"], result.table[1]["count"]
    assert cited + uncited == len(report.findings)
    assert cited == sum(1 for f in report.findings if f.kb_refs)


def test_the_matrix_puts_every_finding_in_exactly_one_cell(report):
    """Conservation in two dimensions. If the cells did not add up to the total, the grid
    would disagree with the KPI printed directly above it on the page."""
    result = rq.run_query(report, rq.QuerySpec(op="matrix"))
    cells = sum(row[column] for row in result.table for column in result.columns)
    assert cells == result.total == len(report.findings)


def test_every_matrix_row_total_is_that_rows_cells(report):
    result = rq.run_query(report, rq.QuerySpec(op="matrix"))
    for row in result.table:
        assert row["count"] == sum(row[column] for column in result.columns)


def test_the_matrix_agrees_cell_by_cell_with_the_findings_on_disk(report):
    """The grid is not a second source of truth — each cell is recounted here straight from
    the report, so a bug in the cross-tab shows up as a mismatch rather than as a plausible
    number nobody checks."""
    result = rq.run_query(report, rq.QuerySpec(op="matrix"))
    for row in result.table:
        for column in result.columns:
            expected = sum(
                1
                for f in report.findings
                if f.severity == row["label"] and f.confidence == column
            )
            assert row[column] == expected, f"{row['label']} × {column}"


def test_the_matrix_axes_follow_the_declared_scales_and_show_empty_levels(report):
    """An absent severity level is information — the row stays, at zero."""
    result = rq.run_query(report, rq.QuerySpec(op="matrix"))
    assert [row["label"] for row in result.table][: len(rq.SEVERITY_ORDER)] == list(
        rq.SEVERITY_ORDER
    )
    assert result.columns[: len(rq.CONFIDENCE_ORDER)] == list(rq.CONFIDENCE_ORDER)


def test_the_matrix_states_its_column_totals_because_the_table_cannot(report):
    """Row totals are a column of the table; column totals are not, so the query layer says
    them out loud rather than leaving `app.py` to add them up (which it may not do)."""
    result = rq.run_query(report, rq.QuerySpec(op="matrix"))
    for column in result.columns:
        total = sum(row[column] for row in result.table)
        assert f"`{column}`: {total}" in (result.note or "")


def test_the_matrix_carries_a_filtered_denominator_like_every_other_op(report):
    result = rq.run_query(report, rq.QuerySpec(op="matrix", filters={"severity": "high"}))
    assert result.total == sum(1 for f in report.findings if f.severity == "high")
    high_row = next(row for row in result.table if row["label"] == "high")
    assert high_row["count"] == result.total


def test_a_matrix_that_matches_nothing_says_no_match_not_no_vulnerabilities(report):
    result = rq.run_query(report, rq.QuerySpec(op="matrix", filters={"cwe": "CWE-99999"}))
    assert result.total == 0
    assert "không phải" in rq.template_answer(result)


def test_the_matrix_narration_names_the_largest_cell(report):
    result = rq.run_query(report, rq.QuerySpec(op="matrix"))
    biggest = max(
        (row[column], row["label"], column)
        for row in result.table
        for column in result.columns
    )
    text = rq.template_answer(result)
    assert str(biggest[0]) in text and biggest[1] in text


def test_matrix_takes_no_dimension_so_its_axes_cannot_be_widened(report):
    """The op set stays closed in both directions: a router cannot turn this into
    `cwe × file` and paint a 25×80 grid."""
    spec = rq.validate_spec(rq.QuerySpec(op="matrix", dimension="cwe"))
    assert spec.dimension is None


def test_overview_reads_the_sidecar_for_run_scoped_values(report):
    result = rq.run_query(report, rq.QuerySpec(op="overview"))
    labels = {row["label"]: row["value"] for row in result.table}
    assert labels["Tổng số phát hiện"] == len(report.findings)
    assert labels["Cảnh báo thô đọc vào"] == report.meta.alerts_read
    assert labels["Trạng thái lần chạy"] == report.meta.status


# --- the deterministic router -----------------------------------------------------


@pytest.mark.parametrize(
    "question,op,dimension",
    [
        ("Tổng quan báo cáo này có gì?", "overview", None),
        ("Phân bố theo mức độ nghiêm trọng ra sao?", "count_by", "severity"),
        ("Ma trận mức độ và độ tin cậy trông thế nào?", "matrix", None),
        ("Cho tôi bảng chéo severity confidence", "matrix", None),
        ("Thống kê theo CWE", "count_by", "cwe"),
        ("Phân bố theo nhóm OWASP", "count_by", "owasp"),
        ("Độ tin cậy phân bố thế nào", "count_by", "confidence"),
        ("Tệp nào bị nhiều lỗi nhất?", "top_files", None),
        ("Độ phủ kho tri thức thế nào?", "kb_coverage", None),
        ("Liệt kê các phát hiện", "list_findings", None),
    ],
)
def test_route_keywords_places_the_common_questions(question, op, dimension):
    spec = rq.route_keywords(question)
    assert (spec.op, spec.dimension) == (op, dimension)


def test_a_pinned_dimension_is_not_a_grouping_dimension():
    """"Liệt kê lỗi CWE-89" mentions `cwe`, but it asks about one CWE. Answering with the
    distribution across all 25 of them would be a different question."""
    spec = rq.route_keywords("Liệt kê các lỗi CWE-89")
    assert spec.op == "list_findings"
    assert spec.filters["cwe"] == "CWE-89"


def test_a_named_file_beats_the_file_ranking_keyword():
    spec = rq.route_keywords("lỗi trong file BenchmarkTest00024.java")
    assert spec.op == "list_findings"
    assert "BenchmarkTest00024" in spec.filters["file"]


def test_a_bare_finding_id_routes_to_lookup(report):
    spec = rq.route_keywords(report.findings[0].finding_id)
    assert spec.op == "lookup"


def test_an_unplaceable_question_becomes_an_overview_not_an_error():
    spec = rq.route_keywords("xin chào bạn khoẻ không")
    assert spec.op == "overview"


def test_every_routed_question_produces_a_runnable_spec(report):
    """The router's contract: it always returns something `run_query` accepts, so the chat
    layer never has to render an error instead of an answer."""
    for question in list(report_chat.SUGGESTED_QUESTIONS) + ["", "???", "CWE-89", "abc xyz"]:
        rq.run_query(report, rq.route_keywords(question))


# --- charts -----------------------------------------------------------------------


@pytest.mark.parametrize("title,op,dimension,_help", report_charts.DASHBOARD_PANELS)
def test_every_dashboard_panel_builds_a_chart(report, title, op, dimension, _help):
    result = rq.run_query(report, rq.QuerySpec(op=op, dimension=dimension, limit=10))
    chart = report_charts.chart_for(result)
    assert chart is not None, f"{title} produced no chart"
    spec = chart.to_dict()
    assert "layer" in spec or "mark" in spec


def test_the_chart_draws_exactly_the_table_it_was_given(report):
    """The chart never re-aggregates. If a bar disagrees with the table below it, that is a
    bug in `report_charts`, not a judgement call."""
    result = rq.run_query(report, rq.QuerySpec(op="count_by", dimension="severity"))
    frame = report_charts.chart_frame(result)
    assert list(frame["count"]) == [row["count"] for row in result.table]
    assert list(frame["label"]) == [row["label"] for row in result.table]


def test_a_wide_distribution_is_capped_but_the_table_is_not(report):
    result = rq.run_query(report, rq.QuerySpec(op="count_by", dimension="cwe"))
    assert len(result.table) > report_charts.MAX_BARS
    assert len(report_charts.chart_frame(result)) == report_charts.MAX_BARS


@pytest.mark.parametrize("op", ["overview", "list_findings", "lookup", "matrix"])
def test_a_result_that_is_not_a_distribution_gets_no_chart(report, op):
    result = rq.run_query(report, rq.QuerySpec(op=op))
    assert report_charts.chart_for(result) is None


def test_an_all_zero_distribution_gets_no_chart(report):
    """An empty rectangle reads as a rendering failure, not as 'nothing matched'."""
    result = rq.run_query(
        report, rq.QuerySpec(op="count_by", dimension="severity", filters={"cwe": "CWE-99999"})
    )
    assert report_charts.chart_for(result) is None


def test_severity_bars_use_the_declared_scale_order(report):
    result = rq.run_query(report, rq.QuerySpec(op="count_by", dimension="severity"))
    spec = json.dumps(report_charts.chart_for(result).to_dict())
    # The colour domain follows DESIGN.md's scale, not alphabetical order.
    assert spec.index('"critical"') < spec.index('"low"')


# --- the hybrid chat: deterministic path ------------------------------------------


def test_no_credentials_answers_deterministically_and_says_so(report, monkeypatch):
    monkeypatch.delenv("OPENCODE_API_KEY", raising=False)
    monkeypatch.delenv("OPENCODE_BASE_URL", raising=False)
    turn = report_chat.answer("Phân bố theo mức độ nghiêm trọng?", report, use_llm=True)
    assert turn.route_source == "keyword"
    assert turn.answer_source == "template"
    assert turn.route_failure == "no_credentials"
    assert turn.tokens == 0
    assert turn.answer


def test_use_llm_false_makes_no_call_even_with_credentials(report, monkeypatch):
    monkeypatch.setenv("OPENCODE_API_KEY", "k")
    monkeypatch.setenv("OPENCODE_BASE_URL", "https://example.invalid")
    monkeypatch.setenv("CUSTOM_SCAN_MODEL", "m")
    # The autouse `_offline` fixture would raise if a call were attempted.
    turn = report_chat.answer("Tổng quan", report, use_llm=False)
    assert (turn.route_source, turn.answer_source) == ("keyword", "template")


def test_the_same_question_twice_offline_gives_the_same_answer(report):
    first = report_chat.answer("Thống kê theo CWE", report, use_llm=False)
    second = report_chat.answer("Thống kê theo CWE", report, use_llm=False)
    assert first.answer == second.answer
    assert first.spec_json == second.spec_json


def test_the_prompt_file_carries_both_sections_and_a_version():
    prompt = report_chat.load_chat_prompt()
    assert prompt.version != "unversioned"
    assert len(prompt.sha256) == 64
    assert agent._section(prompt.text, report_chat.ROUTER_HEADING)
    assert agent._section(prompt.text, report_chat.NARRATOR_HEADING)


def test_a_missing_prompt_file_is_refused_not_defaulted(tmp_path):
    with pytest.raises(agent.PromptMissingError):
        report_chat.load_chat_prompt(tmp_path / "nope.md")


# --- the spend guard --------------------------------------------------------------
#
# The deployed instance is public and unauthenticated, so once it holds a real key the chat
# box is a way to spend money. These tests are about the ceiling on that, and the property
# they protect is: running out of budget degrades to the deterministic path, it never errors
# and it never silently keeps spending.


def test_an_unset_budget_falls_back_to_the_documented_default(monkeypatch):
    monkeypatch.delenv(report_chat.DAILY_TOKEN_BUDGET_ENV, raising=False)
    assert report_chat.daily_token_budget() == report_chat.DEFAULT_DAILY_TOKEN_BUDGET


def test_a_misspelled_budget_fails_toward_the_default_not_toward_unlimited(monkeypatch):
    """Same rule `runtime_mode()` uses for `SCAN_UI_READONLY`, applied to money: a typo must
    never be the thing that uncaps spending on a public endpoint."""
    monkeypatch.setenv(report_chat.DAILY_TOKEN_BUDGET_ENV, "một trăm nghìn")
    assert report_chat.daily_token_budget() == report_chat.DEFAULT_DAILY_TOKEN_BUDGET


@pytest.mark.parametrize("raw", ["0", "-1"])
def test_zero_or_negative_means_no_ceiling(monkeypatch, raw):
    monkeypatch.setenv(report_chat.DAILY_TOKEN_BUDGET_ENV, raw)
    assert report_chat.daily_token_budget() == report_chat.UNLIMITED
    assert report_chat.budget_remaining() is None
    assert report_chat.budget_exhausted() is False


def test_spending_draws_the_budget_down_and_then_stops_it(monkeypatch):
    monkeypatch.setenv(report_chat.DAILY_TOKEN_BUDGET_ENV, "1000")
    assert report_chat.budget_remaining("2026-08-07") == 1000
    report_chat.record_tokens(400, "2026-08-07")
    assert report_chat.budget_remaining("2026-08-07") == 600
    assert report_chat.budget_exhausted("2026-08-07") is False
    report_chat.record_tokens(600, "2026-08-07")
    assert report_chat.budget_exhausted("2026-08-07") is True


def test_overspending_the_last_call_does_not_go_negative(monkeypatch):
    monkeypatch.setenv(report_chat.DAILY_TOKEN_BUDGET_ENV, "100")
    report_chat.record_tokens(9_999, "2026-08-07")
    assert report_chat.budget_remaining("2026-08-07") == 0


def test_a_new_utc_day_refills_the_budget(monkeypatch):
    monkeypatch.setenv(report_chat.DAILY_TOKEN_BUDGET_ENV, "1000")
    report_chat.record_tokens(1000, "2026-08-07")
    assert report_chat.budget_exhausted("2026-08-07") is True
    assert report_chat.budget_remaining("2026-08-08") == 1000


def test_an_exhausted_budget_answers_deterministically_instead_of_calling(report, monkeypatch):
    """The whole point: no model call happens, an answer still comes back, and the turn says
    which path produced it. This is the same path the instance ran on before it had a key."""
    calls = _stub_calls(monkeypatch, [])  # popping from an empty queue would raise
    monkeypatch.setenv(report_chat.DAILY_TOKEN_BUDGET_ENV, "500")
    report_chat.record_tokens(500)

    turn = report_chat.answer("mức độ ra sao", report)

    assert calls == [], "a model call was made with the budget already spent"
    assert (turn.route_source, turn.answer_source) == ("keyword", "template")
    assert turn.route_failure == turn.answer_failure == "budget_exhausted"
    assert turn.tokens == 0
    assert turn.answer, "an exhausted budget must still produce an answer"
    assert turn.result.total == len(report.findings), "the numbers are unaffected"


def test_the_labelled_failure_is_in_the_closed_reason_set():
    assert "budget_exhausted" in report_chat.ROUTE_FAILURE_REASONS
    assert "budget_exhausted" in report_chat.ANSWER_FAILURE_REASONS


def test_a_real_turn_charges_exactly_what_the_provider_reported(report, monkeypatch):
    _stub_calls(
        monkeypatch,
        [
            ('{"op": "count_by", "dimension": "severity", "filters": {}, "limit": 10}', 100, None),
            ("Phần lớn phát hiện nằm ở mức high.", 50, None),
        ],
    )
    monkeypatch.setenv(report_chat.DAILY_TOKEN_BUDGET_ENV, "1000")
    turn = report_chat.answer("mức độ ra sao", report)
    assert turn.tokens == 150
    assert report_chat.tokens_spent() == 150
    assert report_chat.budget_remaining() == 850


def test_a_transport_failure_costs_nothing(report, monkeypatch):
    """A call that never reached the provider reported no usage, so it must not eat budget —
    otherwise an outage would bill the day away and leave the page degraded for no spend."""
    _stub_calls(monkeypatch, [(None, 0, "transport_error"), (None, 0, "transport_error")])
    monkeypatch.setenv(report_chat.DAILY_TOKEN_BUDGET_ENV, "1000")
    report_chat.answer("mức độ ra sao", report)
    assert report_chat.tokens_spent() == 0


def test_a_narration_thrown_out_for_inventing_a_number_still_costs(report, monkeypatch):
    """Billing follows spend, not usefulness. Those tokens were burned at the provider even
    though the answer was discarded, so the ceiling has to see them."""
    _stub_calls(
        monkeypatch,
        [
            ('{"op": "count_by", "dimension": "severity", "filters": {}, "limit": 10}', 100, None),
            ("Có 999999 phát hiện nghiêm trọng.", 70, None),
        ],
    )
    monkeypatch.setenv(report_chat.DAILY_TOKEN_BUDGET_ENV, "1000")
    turn = report_chat.answer("mức độ ra sao", report)
    assert turn.answer_source == "template"
    assert turn.answer_failure == "unsupported_number"
    assert report_chat.tokens_spent() == 170


# --- the hybrid chat: model path, stubbed -----------------------------------------


def _stub_calls(monkeypatch, replies):
    """Feed `_post_chat` a scripted list of `(content, tokens, failure)` tuples."""
    queue = list(replies)
    calls = []

    def fake(messages, model, timeout):
        calls.append(messages)
        return queue.pop(0)

    monkeypatch.setattr(report_chat, "_post_chat", fake)
    monkeypatch.setenv("OPENCODE_API_KEY", "k")
    monkeypatch.setenv("OPENCODE_BASE_URL", "https://example.invalid")
    monkeypatch.setenv("CUSTOM_SCAN_MODEL", "m")
    return calls


def test_a_valid_model_route_and_narration_are_used_and_labelled(report, monkeypatch):
    _stub_calls(
        monkeypatch,
        [
            ('{"op": "count_by", "dimension": "severity", "filters": {}, "limit": 10}', 100, None),
            ("Phần lớn phát hiện nằm ở mức high.", 50, None),
        ],
    )
    turn = report_chat.answer("mức độ ra sao", report)
    assert (turn.route_source, turn.answer_source) == ("llm", "llm")
    assert turn.answer == "Phần lớn phát hiện nằm ở mức high."
    assert turn.tokens == 150
    assert turn.result.dimension == "severity"


def test_a_fenced_route_is_unwrapped_rather_than_wasting_a_fallback(report, monkeypatch):
    _stub_calls(
        monkeypatch,
        [('```json\n{"op": "overview"}\n```', 10, None), ("Tổng quan.", 10, None)],
    )
    turn = report_chat.answer("tổng quan", report)
    assert turn.route_source == "llm"
    assert turn.result.op == "overview"


def test_an_unparseable_route_falls_back_to_keywords_with_a_reason(report, monkeypatch):
    _stub_calls(monkeypatch, [("not json at all", 10, None), ("Lời văn.", 10, None)])
    turn = report_chat.answer("phân bố theo mức độ", report)
    assert turn.route_source == "keyword"
    assert turn.route_failure == "non_json"
    assert turn.result.dimension == "severity"  # the keyword router still placed it
    assert any("định tuyến" in note for note in turn.notes)


def test_a_route_naming_an_operation_that_does_not_exist_is_refused(report, monkeypatch):
    _stub_calls(
        monkeypatch,
        [('{"op": "delete_everything"}', 10, None), ("Lời văn.", 10, None)],
    )
    turn = report_chat.answer("tổng quan", report)
    assert turn.route_source == "keyword"
    assert turn.route_failure == "spec_invalid"


def test_a_transport_failure_on_routing_still_answers(report, monkeypatch):
    _stub_calls(monkeypatch, [(None, 0, "transport_error"), ("Lời văn.", 10, None)])
    turn = report_chat.answer("tệp nào nhiều lỗi nhất", report)
    assert turn.route_source == "keyword"
    assert turn.route_failure == "transport_error"
    assert turn.result.op == "top_files"
    assert turn.answer == "Lời văn."


def test_narration_carrying_an_invented_number_is_rejected(report, monkeypatch):
    """The property this whole design exists for. A model that produces a figure the table
    cannot account for gets thrown away, exactly as the analysis agent throws away a
    model-invented file path — and the turn says so."""
    _stub_calls(
        monkeypatch,
        [
            ('{"op": "count_by", "dimension": "severity"}', 10, None),
            ("Có 4823 phát hiện nghiêm trọng cần xử lý ngay.", 10, None),
        ],
    )
    turn = report_chat.answer("mức độ", report)
    assert turn.answer_source == "template"
    assert turn.answer_failure == "unsupported_number"
    assert "4823" not in turn.answer
    assert any("không có trong bảng" in note for note in turn.notes)


def test_narration_using_only_table_numbers_survives(report, monkeypatch):
    result = rq.run_query(report, rq.QuerySpec(op="count_by", dimension="severity"))
    critical = next(row["count"] for row in result.table if row["label"] == "critical")
    _stub_calls(
        monkeypatch,
        [
            ('{"op": "count_by", "dimension": "severity"}', 10, None),
            (f"Có {critical} phát hiện ở mức critical.", 10, None),
        ],
    )
    turn = report_chat.answer("mức độ", report)
    assert turn.answer_source == "llm"


def test_a_percentage_the_table_supports_is_not_treated_as_invention(report):
    result = rq.run_query(report, rq.QuerySpec(op="kb_coverage"))
    cited = result.table[0]["count"]
    percent = round(100.0 * cited / result.total)
    assert not report_chat._unsupported_numbers(
        f"Khoảng {percent}% phát hiện trích dẫn được tài liệu.", result, "độ phủ kb"
    )


def test_a_cwe_number_from_a_label_is_not_treated_as_invention(report):
    result = rq.run_query(report, rq.QuerySpec(op="count_by", dimension="cwe"))
    assert not report_chat._unsupported_numbers("CWE-89 chiếm nhiều nhất.", result, "cwe")


def test_the_model_is_never_shown_a_file_path_it_could_echo_as_its_own(report, monkeypatch):
    """The router turn lists the report's vocabulary, not its file paths — the same reason
    `security_agent._user_turn` withholds paths from the analysis call."""
    calls = _stub_calls(
        monkeypatch, [('{"op": "overview"}', 10, None), ("Tổng quan.", 10, None)]
    )
    report_chat.answer("tổng quan", report)
    router_user_turn = calls[0][1]["content"]
    assert "BenchmarkTest" not in router_user_turn
    assert ".java" not in router_user_turn


def test_a_turn_always_records_how_it_was_produced(report, monkeypatch):
    _stub_calls(monkeypatch, [(None, 0, "http_error"), (None, 0, "http_error")])
    turn = report_chat.answer("tổng quan", report)
    assert turn.route_source in ("llm", "keyword")
    assert turn.answer_source in ("llm", "template")
    assert turn.spec_json
    assert json.loads(turn.spec_json)["op"] == turn.spec.op
    assert turn.answer  # never empty, whatever failed
