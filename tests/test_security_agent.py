"""C-016 / C-017 — the Security Analysis Agent.

Offline by construction: the `_offline` autouse fixture replaces `requests.post` with a
raiser, so the suite makes **zero** real API calls and a test that forgets to stub the
network fails loudly rather than quietly spending money.

`src/` is not an installed package (the app runs `streamlit run src/app.py`, so `src/` is
the script dir and the modules import each other flatly). Tests put it on the path the
same way rather than inventing a packaging layout the app does not use.
"""
import filecmp
import itertools
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import security_agent as agent  # noqa: E402
from alert_normalizer import Alert  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
REAL_ALERTS = ROOT / "data" / "kb" / "alerts.jsonl"
REAL_ALERT_COUNT = 111


def _alert(**overrides) -> Alert:
    base = dict(
        tool="semgrep",
        severity="medium",
        file_or_url="a.java",
        title="weak-prng.util-random",
        description="java.util.Random is a weak PRNG.",
        rule_id="x.y.weak-prng.util-random",
        cwe="CWE-330",
        line=10,
        source_path="results/fixture.sarif",
    )
    base.update(overrides)
    return Alert(**base)


def _conserved(groups, alerts) -> bool:
    occurrences = sum(group.occurrence_count for group in groups)
    duplicates = sum(group.exact_duplicates_removed for group in groups)
    return occurrences + duplicates == len(alerts)


# --- FR21 scenario 1: empty input -------------------------------------------------


def test_fr21_scenario_empty_absent_file_is_status_empty_not_no_vulnerabilities(tmp_path):
    load = agent.load_alerts(input_path=tmp_path / "does-not-exist.jsonl")
    assert load.alerts == []
    assert load.skipped == []
    assert load.lines_read == 0

    report = agent.analyze(input_path=tmp_path / "does-not-exist.jsonl", no_llm=True)
    assert report.meta.status == "empty"
    assert report.findings == []
    # The meta has to say the INPUT was empty; "0 findings" alone would read as a clean bill.
    assert report.meta.alerts_read == 0
    assert report.meta.alerts_valid == 0
    assert report.meta.alerts_skipped == 0


def test_fr21_scenario_empty_zero_byte_file_is_status_empty():
    zero_byte = FIXTURES / "alerts_empty.jsonl"
    assert zero_byte.stat().st_size == 0

    load = agent.load_alerts(input_path=zero_byte)
    assert (load.alerts, load.skipped, load.lines_read) == ([], [], 0)

    report = agent.analyze(input_path=zero_byte, no_llm=True)
    assert report.meta.status == "empty"
    assert report.findings == []
    assert report.meta.accounted_for is True


# --- FR21 scenario 2: invalid input -----------------------------------------------


def test_fr21_scenario_invalid_bad_lines_are_skipped_by_line_number_and_good_ones_survive():
    load = agent.load_alerts(input_path=FIXTURES / "alerts_mixed.jsonl")

    assert load.lines_read == 7
    assert len(load.alerts) == 3
    assert [alert.cwe for alert in load.alerts] == ["CWE-330", "CWE-22", "CWE-327"]

    assert [(record.line_no, record.reason) for record in load.skipped] == [
        (2, "invalid json"),
        (3, "not an object"),
        (4, "missing field: severity"),
        (6, "bad type: severity"),
    ]
    for record in load.skipped:
        assert record.raw
        assert len(record.raw) <= agent.RAW_LINE_LIMIT

    report = agent.analyze(input_path=FIXTURES / "alerts_mixed.jsonl", no_llm=True)
    assert report.meta.status == "ok"
    assert report.meta.alerts_skipped == 4
    assert report.meta.accounted_for is True


def test_fr21_scenario_invalid_every_record_bad_is_status_invalid_input():
    load = agent.load_alerts(input_path=FIXTURES / "alerts_all_invalid.jsonl")
    assert load.alerts == []
    assert len(load.skipped) == 3

    report = agent.analyze(input_path=FIXTURES / "alerts_all_invalid.jsonl", no_llm=True)
    assert report.meta.status == "invalid_input"
    assert report.findings == []
    # Every offending line survives into the sidecar, with its number and its reason.
    assert [record.line_no for record in report.meta.skipped] == [1, 2, 3]
    assert report.meta.accounted_for is True


def test_invalid_line_raw_is_truncated_to_the_contract_limit(tmp_path):
    path = tmp_path / "long.jsonl"
    path.write_text("x" * 5000 + "\n", encoding="utf-8")
    load = agent.load_alerts(input_path=path)
    assert len(load.skipped[0].raw) == agent.RAW_LINE_LIMIT


# --- FR21 scenario 3: no KB, no model ---------------------------------------------


def test_fr21_scenario_no_kb_no_model_still_yields_a_complete_labelled_finding(monkeypatch):
    monkeypatch.setattr(agent.kb_search, "search_kb", lambda *a, **k: [])
    group = agent.group_alerts([_alert()])[0]

    assert agent.attach_kb(group) == []
    finding = agent.fallback_finding(group, [], agent.NO_LLM_REASON)

    assert finding.analysis_source == "fallback"
    assert finding.confidence == "low"
    assert finding.kb_refs == []
    assert finding.owasp is None
    # Complete: every field a reader needs is populated from the alerts themselves.
    assert finding.finding_id and finding.title and finding.cwe == "CWE-330"
    assert finding.locations[0].file == "a.java"
    assert finding.evidence.raw_message
    assert finding.remediation.how_to_verify and finding.remediation.how_to_fix
    # And it says so in its first sentence, so it cannot pass for a model analysis.
    assert finding.explanation.startswith("Không có phân tích từ mô hình")
    assert agent.NO_LLM_REASON in finding.explanation


def test_no_kb_search_failure_is_logged_and_returns_empty_never_raises(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("KB directory is gone")

    monkeypatch.setattr(agent.kb_search, "search_kb", boom)
    group = agent.group_alerts([_alert()])[0]
    assert agent.attach_kb(group) == []


# --- FR17 conservation ------------------------------------------------------------


def test_conservation_holds_over_the_real_alert_file():
    load = agent.load_alerts(input_path=REAL_ALERTS)
    assert load.lines_read == REAL_ALERT_COUNT
    assert load.skipped == []
    groups = agent.group_alerts(load.alerts)
    assert _conserved(groups, load.alerts)
    assert sum(g.occurrence_count for g in groups) + sum(
        g.exact_duplicates_removed for g in groups
    ) == REAL_ALERT_COUNT


def test_conservation_holds_over_the_empty_list():
    groups = agent.group_alerts([])
    assert groups == []
    assert _conserved(groups, [])


def test_conservation_holds_over_a_single_alert():
    load = agent.load_alerts(input_path=FIXTURES / "alerts_single.jsonl")
    groups = agent.group_alerts(load.alerts)
    assert len(groups) == 1
    assert groups[0].occurrence_count == 1
    assert _conserved(groups, load.alerts)


def test_exact_duplicates_are_counted_not_dropped():
    duplicate = _alert()
    groups = agent.group_alerts([duplicate, _alert(), _alert(file_or_url="b.java")])
    assert len(groups) == 1
    assert groups[0].occurrence_count == 2
    assert groups[0].exact_duplicates_removed == 1
    assert _conserved(groups, [duplicate, duplicate, duplicate])


# --- FR19 clamps ------------------------------------------------------------------


@pytest.mark.parametrize(
    "model_severity,tool_severity",
    list(itertools.product(agent.SEVERITY_RANK, repeat=2)),
)
def test_clamp_severity_truth_table_over_all_25_enum_pairs(model_severity, tool_severity):
    decision = agent.clamp_severity(model_severity, tool_severity)
    model_rank = agent.SEVERITY_RANK[model_severity]
    tool_rank = agent.SEVERITY_RANK[tool_severity]
    distance = model_rank - tool_rank

    assert decision.distance == distance
    assert decision.severity in agent.SEVERITY_RANK
    if abs(distance) <= 1:
        # Within one rank (including exactly equal), the model's value stands.
        assert decision.severity == model_severity
        assert decision.clamped is False
    else:
        assert decision.clamped is True
        moved = agent.SEVERITY_RANK[decision.severity] - tool_rank
        assert abs(moved) == 1
        # It moves TOWARD the model, never away from it and never past it.
        assert (moved > 0) == (distance > 0)
        assert abs(agent.SEVERITY_RANK[decision.severity] - model_rank) < abs(distance)


def test_clamp_severity_rejects_a_value_outside_the_enum():
    with pytest.raises(ValueError):
        agent.clamp_severity("catastrophic", "high")


def _hit(doc_id="examples/weak-prng"):
    return agent.kb_search.KBHit(
        doc_id=doc_id, title="t", path="p", score=0.5, snippet="s", category="examples", body="b"
    )


def test_clamp_confidence_fallback_path_floors_to_low():
    group = agent.group_alerts([_alert(), _alert(file_or_url="b.java")])[0]
    decision = agent.clamp_confidence("high", group, [_hit()], "fallback")
    assert decision.confidence == "low"
    assert "fallback" in decision.reason


def test_clamp_confidence_model_says_high_but_kb_empty_gives_low():
    group = agent.group_alerts([_alert(), _alert(file_or_url="b.java")])[0]
    decision = agent.clamp_confidence("high", group, [], "llm")
    assert decision.confidence == "low"
    assert "knowledge-base" in decision.reason


def test_clamp_confidence_high_needs_repeat_or_multi_tool_else_medium():
    single = agent.group_alerts([_alert()])[0]
    assert agent.clamp_confidence("high", single, [_hit()], "llm").confidence == "medium"

    repeated = agent.group_alerts([_alert(), _alert(file_or_url="b.java")])[0]
    assert agent.clamp_confidence("high", repeated, [_hit()], "llm").confidence == "high"

    # Two tools reporting the same weakness class is the other route to high. Metis
    # carries no rule id, so it only lands in the same family when its title slugifies to
    # the segment semgrep's rule id ends in.
    multi_tool = agent.group_alerts(
        [_alert(), _alert(tool="metis", rule_id=None, title="util-random", file_or_url="b.java")]
    )
    assert len(multi_tool) == 1
    assert multi_tool[0].tools == ["metis", "semgrep"]
    assert agent.clamp_confidence("high", multi_tool[0], [_hit()], "llm").confidence == "high"


def test_clamp_confidence_accepts_a_model_value_that_needs_no_floor():
    group = agent.group_alerts([_alert()])[0]
    decision = agent.clamp_confidence("medium", group, [_hit()], "llm")
    assert decision.confidence == "medium"
    assert decision.reason == "model value accepted"


# --- ADR 26 regression ------------------------------------------------------------


def test_two_weak_prng_rules_sharing_cwe_330_do_not_merge():
    """The concrete regression ADR 26 exists to prevent: grouping by CWE alone would put
    `util-random` and `math-random` in one finding whose remediation differs per rule."""
    load = agent.load_alerts(input_path=REAL_ALERTS)
    groups = agent.group_alerts(load.alerts)
    families = {group.group_key: group for group in groups}

    assert "CWE-330::util-random" in families
    assert "CWE-330::math-random" in families
    assert families["CWE-330::util-random"] is not families["CWE-330::math-random"]
    assert families["CWE-330::util-random"].occurrence_count == 10
    assert families["CWE-330::math-random"].occurrence_count == 3


def test_groups_are_sorted_severity_then_occurrences_then_key():
    load = agent.load_alerts(input_path=REAL_ALERTS)
    groups = agent.group_alerts(load.alerts)
    keys = [
        (-agent.SEVERITY_RANK[g.tool_severity], -g.occurrence_count, g.group_key) for g in groups
    ]
    assert keys == sorted(keys)


# --- FR19/FR20 byte-identical rerun + serialization --------------------------------


def test_two_no_llm_runs_write_byte_identical_findings(tmp_path):
    first = agent.write_report(
        agent.analyze(input_path=FIXTURES / "alerts_mixed.jsonl", no_llm=True), tmp_path / "one"
    )
    second = agent.write_report(
        agent.analyze(input_path=FIXTURES / "alerts_mixed.jsonl", no_llm=True), tmp_path / "two"
    )
    assert filecmp.cmp(first.jsonl_path, second.jsonl_path, shallow=False)
    assert (
        Path(first.jsonl_path).read_bytes() == Path(second.jsonl_path).read_bytes()
    )


def test_report_jsonl_is_pure_jsonl_with_no_header_record(tmp_path):
    report = agent.analyze(input_path=FIXTURES / "alerts_mixed.jsonl", no_llm=True)
    result = agent.write_report(report, tmp_path)
    lines = Path(result.jsonl_path).read_text(encoding="utf-8").splitlines()

    assert len(lines) == result.findings_written == report.meta.findings
    for line in lines:
        record = json.loads(line)
        assert "finding_id" in record and "status" not in record


def test_run_scoped_values_live_only_in_the_sidecar(tmp_path):
    report = agent.analyze(input_path=FIXTURES / "alerts_mixed.jsonl", no_llm=True)
    result = agent.write_report(report, tmp_path)
    findings_text = Path(result.jsonl_path).read_text(encoding="utf-8")
    assert report.meta.generated_at not in findings_text

    meta = json.loads(Path(result.meta_path).read_text(encoding="utf-8"))
    assert meta["generated_at"] and "duration_seconds" in meta


def test_load_report_round_trips_and_returns_none_when_absent(tmp_path):
    assert agent.load_report(tmp_path / "nothing") is None

    written = agent.analyze(input_path=FIXTURES / "alerts_mixed.jsonl", no_llm=True)
    agent.write_report(written, tmp_path)
    read_back = agent.load_report(tmp_path)

    assert read_back is not None
    assert len(read_back.findings) == len(written.findings)
    assert read_back.findings[0] == written.findings[0]
    assert read_back.meta == written.meta


def test_load_report_raises_on_a_findings_line_that_will_not_parse(tmp_path):
    agent.write_report(
        agent.analyze(input_path=FIXTURES / "alerts_mixed.jsonl", no_llm=True), tmp_path
    )
    path = tmp_path / agent.REPORT_FILENAME
    path.write_text(path.read_text(encoding="utf-8") + "{not json}\n", encoding="utf-8")

    with pytest.raises(agent.ReportCorruptError):
        agent.load_report(tmp_path)


def test_write_report_touches_nothing_outside_its_out_dir(tmp_path):
    before = REAL_ALERTS.read_bytes()
    agent.write_report(agent.analyze(input_path=REAL_ALERTS, no_llm=True), tmp_path)
    assert REAL_ALERTS.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(
        [agent.META_FILENAME, agent.REPORT_FILENAME]
    )


# --- the LLM path is C-017's, and says so ------------------------------------------


def test_limit_still_produces_a_finding_for_every_group(tmp_path):
    """--limit caps how many groups reach the model; the remainder must still appear,
    otherwise the report's own arithmetic would lie about what was analysed."""
    report = agent.analyze(input_path=REAL_ALERTS, no_llm=True, limit=5)
    assert report.meta.limit_applied == 5
    assert report.meta.findings == report.meta.groups
    assert report.meta.accounted_for is True


# ==================================================================================
# C-017 — the bounded model call and the guards. Every network call below is stubbed:
# the suite makes ZERO real API calls, so `uv run pytest` stays offline and free.
# ==================================================================================


VALID_MODEL_REPLY = {
    "title_vi": "Dùng bộ sinh số ngẫu nhiên yếu",
    "explanation_vi": "java.util.Random đoán được nên không dùng cho giá trị bí mật.",
    "how_to_verify_vi": "Kiểm tra giá trị sinh ra có dùng làm token hay không.",
    "how_to_fix_vi": "Thay bằng java.security.SecureRandom.",
    "code_hint": "SecureRandom rnd = new SecureRandom();",
    "severity": "high",
    "severity_rationale_vi": "Nâng một bậc vì giá trị dùng cho token xác thực.",
    "confidence": "high",
    "kb_doc_ids": ["examples/weak-prng"],
}


class _StubResponse:
    def __init__(self, status_code=200, payload=None, body_is_json=True):
        self.status_code = status_code
        self._payload = payload
        self._body_is_json = body_is_json

    def json(self):
        if not self._body_is_json:
            raise ValueError("not json")
        return self._payload


def _chat_payload(content, total_tokens=420):
    return {
        "choices": [{"message": {"content": content}}],
        "usage": {"total_tokens": total_tokens},
    }


class _Recorder:
    """Stands in for the POST. Records every call so a test can assert the CALL COUNT —
    which is how "exactly one retry, never three" gets proven rather than assumed."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, **kwargs):
        self.calls.append((url, kwargs))
        response = self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]
        if isinstance(response, Exception):
            raise response
        return response


@pytest.fixture
def prompt():
    return agent.load_system_prompt()


@pytest.fixture
def group():
    return agent.group_alerts(
        [_alert(), _alert(file_or_url="b.java"), _alert(file_or_url="c.java")]
    )[0]


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """The suite makes zero real calls, and that is enforced rather than hoped for: the
    default `post` raises, so a test that forgets to stub the network fails loudly instead
    of quietly spending money."""
    monkeypatch.setenv("OPENCODE_BASE_URL", "https://stub.invalid/v1")
    monkeypatch.setenv("OPENCODE_API_KEY", "")
    monkeypatch.setenv("CUSTOM_SCAN_MODEL", "stub-model")

    def unstubbed(*args, **kwargs):
        raise AssertionError("a test reached the real network — every call must be stubbed")

    monkeypatch.setattr(agent.requests, "post", unstubbed)


# --- the prompt (ADR 28) ----------------------------------------------------------


def test_load_system_prompt_reads_version_and_a_stable_sha256(prompt):
    assert prompt.path == "src/prompts/security_analyst.md"
    assert prompt.version == "1.0.0"
    assert len(prompt.sha256) == 64
    assert prompt.sha256 == agent.load_system_prompt().sha256
    assert prompt.text.strip()


def test_load_system_prompt_raises_when_the_file_is_missing(tmp_path):
    with pytest.raises(agent.PromptMissingError):
        agent.load_system_prompt(tmp_path / "nope.md")


def test_load_system_prompt_raises_on_an_empty_file(tmp_path):
    empty = tmp_path / "empty.md"
    empty.write_text("   \n", encoding="utf-8")
    with pytest.raises(agent.PromptMissingError):
        agent.load_system_prompt(empty)


# --- one test per failure_reason, each still yielding a complete fallback ----------


def _assert_complete_fallback(finding):
    assert finding.analysis_source == "fallback"
    assert finding.confidence == "low"
    assert finding.model is None
    assert finding.explanation.startswith("Không có phân tích từ mô hình")
    assert finding.remediation.how_to_verify and finding.remediation.how_to_fix
    assert finding.locations and finding.evidence.raw_message


def test_failure_transport_error(monkeypatch, prompt, group):
    recorder = _Recorder(requests_exception := agent.requests.ConnectionError("no route"))
    monkeypatch.setattr(agent.requests, "post", recorder)
    analysis = agent.analyze_group(group, [], prompt)
    assert analysis.ok is False
    assert analysis.failure_reason == "transport_error"
    # Not retried: retrying a dead socket buys nothing and still costs a round trip.
    assert len(recorder.calls) == 1
    _assert_complete_fallback(agent.build_finding(group, [], analysis, prompt))
    assert requests_exception


def test_failure_http_error(monkeypatch, prompt, group):
    monkeypatch.setattr(agent.requests, "post", _Recorder(_StubResponse(status_code=403)))
    analysis = agent.analyze_group(group, [], prompt)
    assert analysis.failure_reason == "http_error"
    _assert_complete_fallback(agent.build_finding(group, [], analysis, prompt))


def test_failure_non_json_body(monkeypatch, prompt, group):
    monkeypatch.setattr(
        agent.requests, "post", _Recorder(_StubResponse(payload=None, body_is_json=False))
    )
    analysis = agent.analyze_group(group, [], prompt)
    assert analysis.failure_reason == "non_json"
    _assert_complete_fallback(agent.build_finding(group, [], analysis, prompt))


def test_failure_empty_response(monkeypatch, prompt, group):
    monkeypatch.setattr(
        agent.requests, "post", _Recorder(_StubResponse(payload=_chat_payload("   ")))
    )
    analysis = agent.analyze_group(group, [], prompt)
    assert analysis.failure_reason == "empty_response"
    _assert_complete_fallback(agent.build_finding(group, [], analysis, prompt))


def test_failure_zero_tokens_a_200_that_reports_no_work_is_not_a_success(
    monkeypatch, prompt, group
):
    """ADR 30 — the exact week-2 incident. A perfectly-shaped 200 carrying a perfectly
    valid finding is STILL a failure when it claims zero tokens were spent."""
    payload = _chat_payload(json.dumps(VALID_MODEL_REPLY), total_tokens=0)
    monkeypatch.setattr(agent.requests, "post", _Recorder(_StubResponse(payload=payload)))

    analysis = agent.analyze_group(group, [], prompt)
    assert analysis.ok is False
    assert analysis.failure_reason == "zero_tokens"
    assert analysis.total_tokens == 0
    _assert_complete_fallback(agent.build_finding(group, [], analysis, prompt))


def test_failure_zero_tokens_also_covers_a_reply_with_no_usage_block(
    monkeypatch, prompt, group
):
    payload = {"choices": [{"message": {"content": json.dumps(VALID_MODEL_REPLY)}}]}
    monkeypatch.setattr(agent.requests, "post", _Recorder(_StubResponse(payload=payload)))
    assert agent.analyze_group(group, [], prompt).failure_reason == "zero_tokens"


def test_failure_schema_invalid_when_no_retry_is_allowed(monkeypatch, prompt, group):
    broken = dict(VALID_MODEL_REPLY)
    del broken["how_to_fix_vi"]
    monkeypatch.setattr(
        agent.requests,
        "post",
        _Recorder(_StubResponse(payload=_chat_payload(json.dumps(broken)))),
    )
    analysis = agent.analyze_group(group, [], prompt, allow_retry=False)
    assert analysis.failure_reason == "schema_invalid"
    assert "how_to_fix_vi" in analysis.failure_detail
    _assert_complete_fallback(agent.build_finding(group, [], analysis, prompt))


def test_failure_retry_exhausted(monkeypatch, prompt, group):
    monkeypatch.setattr(
        agent.requests,
        "post",
        _Recorder(_StubResponse(payload=_chat_payload("this is not json"))),
    )
    analysis = agent.analyze_group(group, [], prompt)
    assert analysis.failure_reason == "retry_exhausted"
    _assert_complete_fallback(agent.build_finding(group, [], analysis, prompt))


def test_every_closed_set_reason_is_reachable():
    """The set is closed so the sidecar can be counted rather than grepped — which is only
    true if no code path invents a reason outside it."""
    assert set(agent.FAILURE_REASONS) == {
        "transport_error",
        "http_error",
        "empty_response",
        "zero_tokens",
        "non_json",
        "schema_invalid",
        "retry_exhausted",
    }


# --- exactly one retry ------------------------------------------------------------


def test_a_schema_invalid_reply_retries_exactly_once_then_falls_back(
    monkeypatch, prompt, group
):
    broken = dict(VALID_MODEL_REPLY, severity="catastrophic")
    recorder = _Recorder(_StubResponse(payload=_chat_payload(json.dumps(broken))))
    monkeypatch.setattr(agent.requests, "post", recorder)

    analysis = agent.analyze_group(group, [], prompt)
    assert len(recorder.calls) == 2, "one call plus one retry — never three"
    assert analysis.failure_reason == "retry_exhausted"
    assert analysis.calls == 2

    # The retry has to NAME the error, otherwise it is just the same roll of the dice.
    retry_messages = recorder.calls[1][1]["json"]["messages"]
    assert retry_messages[-1]["role"] == "user"
    assert "severity" in retry_messages[-1]["content"]


def test_a_retry_that_succeeds_yields_an_llm_finding(monkeypatch, prompt, group):
    recorder = _Recorder(
        _StubResponse(payload=_chat_payload("{oops")),
        _StubResponse(payload=_chat_payload(json.dumps(VALID_MODEL_REPLY))),
    )
    monkeypatch.setattr(agent.requests, "post", recorder)

    analysis = agent.analyze_group(group, [], prompt)
    assert analysis.ok is True
    assert len(recorder.calls) == 2
    assert analysis.total_tokens == 840


def test_a_fenced_reply_is_unwrapped_rather_than_burning_a_paid_retry(
    monkeypatch, prompt, group
):
    fenced = "```json\n" + json.dumps(VALID_MODEL_REPLY) + "\n```"
    recorder = _Recorder(_StubResponse(payload=_chat_payload(fenced)))
    monkeypatch.setattr(agent.requests, "post", recorder)

    assert agent.analyze_group(group, [], prompt).ok is True
    assert len(recorder.calls) == 1


# --- the model is not believed about facts ----------------------------------------


def test_a_model_claiming_paths_cwes_and_unknown_kb_ids_has_all_three_discarded(
    monkeypatch, prompt, group
):
    liar = dict(
        VALID_MODEL_REPLY,
        explanation_vi="Lỗi nằm ở /etc/passwd dòng 9999, thuộc CWE-1337.",
        kb_doc_ids=["examples/weak-prng", "examples/does-not-exist", "made/up/doc"],
    )
    # The model is also handed an extra top-level key it did not ask for — rejected.
    monkeypatch.setattr(
        agent.requests,
        "post",
        _Recorder(_StubResponse(payload=_chat_payload(json.dumps(liar)))),
    )
    hits = [_hit("examples/weak-prng"), _hit("owasp-top10/A02-cryptographic-failures")]
    analysis = agent.analyze_group(group, hits, prompt)

    assert analysis.ok is True
    assert analysis.dropped_kb_ids == 2

    finding = agent.build_finding(group, hits, analysis, prompt)
    # Locations and CWE come from the alerts, not from the sentence above.
    assert [location.file for location in finding.locations] == ["a.java", "b.java", "c.java"]
    assert finding.cwe == "CWE-330"
    assert finding.kb_refs == ["examples/weak-prng"]
    assert "examples/does-not-exist" not in finding.kb_refs
    assert finding.analysis_source == "llm"
    assert finding.prompt_sha256 == prompt.sha256


def test_an_extra_top_level_key_is_schema_invalid(monkeypatch, prompt, group):
    extra = dict(VALID_MODEL_REPLY, file_path="/etc/passwd")
    monkeypatch.setattr(
        agent.requests,
        "post",
        _Recorder(_StubResponse(payload=_chat_payload(json.dumps(extra)))),
    )
    analysis = agent.analyze_group(group, [], prompt, allow_retry=False)
    assert analysis.failure_reason == "schema_invalid"
    assert "file_path" in analysis.failure_detail


def test_the_user_turn_never_hands_the_model_a_path_or_a_line_number(group):
    turn = agent._user_turn(group, [])
    assert "a.java" not in turn
    assert str(group.occurrences[0].line) not in turn.split("Số lần xuất hiện")[0]
    assert group.title in turn and group.cwe in turn


def test_a_severity_more_than_one_rank_away_is_clamped_in_the_finding(
    monkeypatch, prompt, group
):
    # group tool severity is medium; the model proposes critical, two ranks up.
    bold = dict(VALID_MODEL_REPLY, severity="critical")
    monkeypatch.setattr(
        agent.requests,
        "post",
        _Recorder(_StubResponse(payload=_chat_payload(json.dumps(bold)))),
    )
    finding = agent.build_finding(
        group, [_hit()], agent.analyze_group(group, [_hit()], prompt), prompt
    )
    assert finding.severity_source == "medium"
    assert finding.severity == "high"
    assert finding.severity_clamped is True


# --- degraded vs ok ---------------------------------------------------------------


def test_every_group_failing_gives_status_degraded_and_a_written_report(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(agent.requests, "post", _Recorder(_StubResponse(status_code=500)))
    report = agent.analyze(input_path=FIXTURES / "alerts_mixed.jsonl", no_llm=False)

    assert report.meta.status == "degraded"
    assert report.meta.groups == report.meta.llm_failures
    assert report.meta.llm_failure_reasons == {"http_error": report.meta.groups}
    # Degraded is not empty: the findings still exist and are clearly labelled.
    assert report.findings and all(f.analysis_source == "fallback" for f in report.findings)
    result = agent.write_report(report, tmp_path)
    assert result.findings_written == report.meta.findings


def test_some_groups_failing_stays_ok_with_llm_failures_counted(monkeypatch):
    good = _StubResponse(payload=_chat_payload(json.dumps(VALID_MODEL_REPLY)))
    calls = {"n": 0}

    def flaky(url, **kwargs):
        calls["n"] += 1
        # First group succeeds; everything after it fails at transport.
        if calls["n"] == 1:
            return good
        raise agent.requests.ConnectionError("dropped")

    monkeypatch.setattr(agent.requests, "post", flaky)
    report = agent.analyze(input_path=FIXTURES / "alerts_mixed.jsonl", no_llm=False)

    assert report.meta.status == "ok"
    assert report.meta.llm_failures == report.meta.groups - 1
    assert report.meta.llm_failure_reasons == {"transport_error": report.meta.groups - 1}
    assert sum(1 for f in report.findings if f.analysis_source == "llm") == 1
    assert report.meta.total_tokens == 420


def test_the_prompt_sha256_from_the_run_lands_in_the_sidecar(monkeypatch, tmp_path):
    monkeypatch.setattr(
        agent.requests,
        "post",
        _Recorder(_StubResponse(payload=_chat_payload(json.dumps(VALID_MODEL_REPLY)))),
    )
    report = agent.analyze(input_path=FIXTURES / "alerts_single.jsonl", no_llm=False)
    result = agent.write_report(report, tmp_path)

    meta = json.loads(Path(result.meta_path).read_text(encoding="utf-8"))
    assert meta["prompt_sha256"] == agent.load_system_prompt().sha256
    assert meta["prompt_version"] == "1.0.0"
    assert meta["prompt_path"] == "src/prompts/security_analyst.md"
    assert meta["model"] == "stub-model"


def test_limit_sends_only_the_head_to_the_model_and_labels_the_rest(monkeypatch):
    recorder = _Recorder(_StubResponse(payload=_chat_payload(json.dumps(VALID_MODEL_REPLY))))
    monkeypatch.setattr(agent.requests, "post", recorder)
    report = agent.analyze(input_path=FIXTURES / "alerts_mixed.jsonl", no_llm=False, limit=1)

    assert len(recorder.calls) == 1, "--limit is a cost cap, so it must cap the CALLS"
    assert report.meta.findings == report.meta.groups
    assert sum(1 for f in report.findings if f.analysis_source == "llm") == 1
    skipped = [f for f in report.findings if f.analysis_source == "fallback"]
    assert all(agent.LIMIT_REASON in f.explanation for f in skipped)


def test_analyze_raises_when_the_prompt_file_is_missing(monkeypatch):
    monkeypatch.setattr(agent, "PROMPT_PATH", Path("/nowhere/security_analyst.md"))
    with pytest.raises(agent.PromptMissingError):
        agent.analyze(input_path=FIXTURES / "alerts_single.jsonl", no_llm=False)


def test_no_llm_runs_need_no_prompt_and_make_no_call(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("no_llm=True must not touch the network")

    monkeypatch.setattr(agent.requests, "post", forbidden)
    monkeypatch.setattr(agent, "PROMPT_PATH", Path("/nowhere/security_analyst.md"))
    report = agent.analyze(input_path=FIXTURES / "alerts_single.jsonl", no_llm=True)
    assert report.meta.llm_calls == 0
    assert report.meta.total_tokens is None


# --- cost estimate (FR5-shaped guard) ---------------------------------------------


def test_estimate_analysis_cost_warns_whenever_a_paid_call_would_happen():
    groups = agent.group_alerts(agent.load_alerts(input_path=REAL_ALERTS).alerts)

    full = agent.estimate_analysis_cost(groups, model="m")
    assert full.call_count == full.group_count == len(groups)
    assert str(len(groups)) in full.warning_text

    capped = agent.estimate_analysis_cost(groups, limit=3, model="m")
    assert capped.call_count == 3
    assert capped.group_count == len(groups)
    assert "3" in capped.warning_text and "--limit" in capped.warning_text

    assert agent.estimate_analysis_cost([], model="m").warning_text == ""
    assert agent.estimate_analysis_cost(groups, limit=0, model="m").warning_text == ""
