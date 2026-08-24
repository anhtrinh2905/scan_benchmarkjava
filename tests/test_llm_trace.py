"""`llm_trace.py` — the LangSmith tracing layer around every LLM call.

Offline by construction, twice over: no test here lets a real `_Sender` exist
(the `traced` fixture installs a fake that collects runs in a list), and
`tests/conftest.py` turns tracing off process-wide so the rest of the suite
cannot ship a trace either.

What is worth testing about telemetry is exactly what would be silent if it
broke: that it is off when unconfigured, that the run tree is shaped so
LangSmith can nest it, that secrets never leave, and that nothing it does can
fail the LLM call it wraps.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import llm_trace  # noqa: E402


class FakeSender:
    """Stands in for the background poster. Same duck type `_sender()` returns."""

    class config:  # a namespace the fake exposes, not a class the code instantiates
        project = "test-project"
        endpoint = "https://example.invalid"
        api_key = "fake"

    def __init__(self) -> None:
        self.runs: list[dict] = []

    def submit(self, run: dict) -> None:
        self.runs.append(run)


@pytest.fixture
def traced(monkeypatch):
    """Tracing on, with a fake sender. Restores whatever the process had."""
    state = llm_trace._shared_state()
    previous = state.sender
    sender = FakeSender()
    state.sender = sender
    yield sender
    state.sender = previous


@pytest.fixture
def untraced(monkeypatch, tmp_path):
    """No key anywhere: real environment cleared, `.env` search pointed at an
    empty directory so the repo's own `.env` cannot leak a key into the test."""
    state = llm_trace._shared_state()
    previous = state.sender
    state.sender = None
    for name in ("LANGSMITH_API_KEY", "LANGCHAIN_API_KEY", "LANGSMITH_TRACING",
                 "LANGCHAIN_TRACING_V2", "LANGCHAIN_TRACING"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(llm_trace, "_env_files", lambda: [tmp_path / ".env"])
    yield
    state.sender = previous


# --- off by default ---------------------------------------------------------


def test_disabled_without_key(untraced):
    assert llm_trace.enabled() is False
    assert llm_trace.status()["enabled"] is False


def test_placeholder_key_is_not_a_key(untraced, monkeypatch):
    """`.env.example` ships `LANGSMITH_API_KEY=...`; a copied example must not
    turn every run into a 401 against LangSmith."""
    monkeypatch.setenv("LANGSMITH_API_KEY", "...")
    assert llm_trace._Config().enabled is False


def test_switch_forces_off_with_a_real_key(monkeypatch):
    monkeypatch.setenv("LANGSMITH_API_KEY", "lsv2_pt_real_looking_key")
    monkeypatch.setenv("LANGSMITH_TRACING", "0")
    assert llm_trace._Config().enabled is False


def test_dead_span_accepts_the_whole_api(untraced):
    """Call sites use the context manager unconditionally, so every setter has
    to be a no-op rather than something the caller guards."""
    with llm_trace.trace_llm("x", model="m", messages=[{"role": "user", "content": "hi"}]) as span:
        span.set_metadata(anything=1)
        span.set_outputs(text="ok")
        span.record_llm_response(content="ok", usage={"total_tokens": 5})
        span.set_error("boom")
    assert span.live is False


# --- the run tree -----------------------------------------------------------


def test_llm_run_shape(traced):
    with llm_trace.trace_llm(
        "analysis",
        model="glm-5.1",
        messages=[{"role": "user", "content": "xin chào"}],
        metadata={"group_key": "g1"},
    ) as span:
        span.record_llm_response(
            content="đã xong",
            usage={"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14},
            finish_reason="stop",
        )

    (run,) = traced.runs
    assert run["name"] == "analysis"
    assert run["run_type"] == "llm"
    assert run["session_name"] == "test-project"
    assert run["inputs"]["messages"] == [{"role": "user", "content": "xin chào"}]
    assert run["outputs"]["choices"][0]["message"]["content"] == "đã xong"
    assert run["outputs"]["choices"][0]["finish_reason"] == "stop"
    assert run["outputs"]["usage_metadata"] == {
        "input_tokens": 10,
        "output_tokens": 4,
        "total_tokens": 14,
    }
    assert run["extra"]["metadata"]["ls_model_name"] == "glm-5.1"
    assert run["extra"]["metadata"]["group_key"] == "g1"
    assert run["start_time"] <= run["end_time"]
    assert "parent_run_id" not in run
    assert run["trace_id"] == run["id"]
    assert run["dotted_order"].endswith(run["id"])


def test_a_call_nests_under_the_step_that_made_it(traced):
    with llm_trace.trace_step("analyze", inputs={"groups": 2}):
        with llm_trace.trace_llm("call", model="m", messages=[]):
            pass
        with llm_trace.trace_llm("retry", model="m", messages=[]):
            pass

    call, retry, step = traced.runs  # children finish first
    assert step["name"] == "analyze"
    assert step["run_type"] == "chain"
    for child in (call, retry):
        assert child["parent_run_id"] == step["id"]
        assert child["trace_id"] == step["trace_id"]
        assert child["dotted_order"].startswith(step["dotted_order"] + ".")
    # Siblings are ordered by dotted_order, which is what LangSmith sorts on.
    assert call["dotted_order"] < retry["dotted_order"]


def test_usage_absent_means_no_token_counts(traced):
    with llm_trace.trace_llm("call", model="m", messages=[]) as span:
        span.record_llm_response(content="ok", usage={})
    (run,) = traced.runs
    assert "usage_metadata" not in run["outputs"]


def test_embedding_runs_carry_their_own_type(traced):
    with llm_trace.trace_llm(
        "kb.embed", model="text-embedding-3-small", inputs={"input": "sql injection"},
        run_type="embedding",
    ) as span:
        span.set_outputs(dimensions=1536)
    (run,) = traced.runs
    assert run["run_type"] == "embedding"
    assert run["inputs"] == {"input": "sql injection"}
    assert "messages" not in run["inputs"]


# --- failure is recorded, not raised ---------------------------------------


def test_exception_is_recorded_and_re_raised(traced):
    with pytest.raises(ValueError), llm_trace.trace_step("step"):
        raise ValueError("nổ")
    (run,) = traced.runs
    assert run["error"] == "ValueError: nổ"


def test_a_broken_sender_cannot_fail_the_call(traced, monkeypatch):
    def explode(_run):
        raise RuntimeError("queue is on fire")

    monkeypatch.setattr(traced, "submit", explode)
    with llm_trace.trace_llm("call", model="m", messages=[]) as span:
        span.record_llm_response(content="ok")
    assert span.live is True  # it tried, and swallowed the failure


def test_finish_is_idempotent(traced):
    with llm_trace.trace_step("step") as span:
        pass
    span.finish()
    assert len(traced.runs) == 1


# --- hygiene ----------------------------------------------------------------


def test_secrets_are_redacted_from_the_wire(monkeypatch):
    monkeypatch.setenv("OPENCODE_API_KEY", "sk-a-very-real-looking-key")
    assert "sk-a-very" not in llm_trace._redact("Authorization: Bearer sk-a-very-real-looking-key")
    assert "***REDACTED***" in llm_trace._redact("Bearer sk-a-very-real-looking-key")


def test_short_env_values_are_not_treated_as_secrets(monkeypatch):
    """A three-character `GITHUB_TOKEN` is not a credential, and substituting it
    would corrupt ordinary prose."""
    monkeypatch.setenv("GITHUB_TOKEN", "abc")
    assert llm_trace._redact("abcdefg") == "abcdefg"


def test_long_fields_are_clipped():
    clipped = llm_trace._clip("x" * (llm_trace.MAX_FIELD_CHARS + 500))
    assert clipped.startswith("x" * 100)
    assert "bị cắt" in clipped
    assert len(clipped) < llm_trace.MAX_FIELD_CHARS + 200


def test_clipping_reaches_inside_messages(traced):
    long_prompt = "y" * (llm_trace.MAX_FIELD_CHARS * 3)
    messages = [{"role": "user", "content": long_prompt}]
    with llm_trace.trace_llm("call", model="m", messages=messages):
        pass
    (run,) = traced.runs
    content = run["inputs"]["messages"][0]["content"]
    assert len(content) < llm_trace.MAX_FIELD_CHARS + 100
    assert "bị cắt" in content


def test_the_key_never_reaches_a_repr():
    config = llm_trace._Config.__new__(llm_trace._Config)
    config.api_key = "lsv2_pt_secret"
    config.endpoint = "https://example.invalid"
    config.project = "p"
    config.enabled = True
    assert "lsv2_pt_secret" not in repr(config)
