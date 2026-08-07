"""Hybrid Q&A over a generated analysis report (v1.8 increment).

Library-style seam like the rest of `src/`: no Streamlit, no CLI, no process termination.
The only I/O is the two bounded model calls, and both are optional.

The division of labour is the point of this module, and it is the same one
`security_agent.py` already makes for reports, applied to conversation:

    câu hỏi ──► [1] định tuyến ──► QuerySpec ──► run_query() ──► QueryResult ──► [2] diễn giải
                 model HOẶC từ khoá            (thuần Python)                     model HOẶC mẫu

**The model never counts.** Step [1] picks *which* question to ask the report; step [2]
writes prose about an answer that was already computed. Every number on screen comes out
of `report_query`, and `_unsupported_numbers()` enforces that after the fact by rejecting a
narration containing a figure the table does not support.

**Two calls, both optional, both individually recoverable.** A routing failure falls back
to `report_query.route_keywords()`; a narration failure falls back to
`report_query.template_answer()`. Every `ChatTurn` records which path it actually took, so
a degraded answer is labelled on screen rather than passing for a model answer. With no
credentials at all — the permanent state of the deployed instance (ADR 19) — both
fallbacks engage and the page still answers, just more plainly.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import report_query
from report_query import QueryResult, QuerySpec, QuerySpecError
from security_agent import (
    CALL_TIMEOUT_SECONDS,
    ROOT,
    PromptMissingError,
    SystemPrompt,
    _post_chat,
    _section,
    load_system_prompt,
)

CHAT_PROMPT_PATH = ROOT / "src" / "prompts" / "report_chat.md"

ROUTER_HEADING = "Định tuyến"
NARRATOR_HEADING = "Diễn giải"

RouteSource = Literal["llm", "keyword"]
AnswerSource = Literal["llm", "template"]

# The closed failure set, same discipline as `security_agent.FAILURE_REASONS`: a counted
# reason beats a grepped one. Transport-level reasons come through from `_post_chat`.
ROUTE_FAILURE_REASONS = (
    "no_credentials",
    "prompt_missing",
    "non_json",
    "spec_invalid",
    "budget_exhausted",
)
ANSWER_FAILURE_REASONS = (
    "no_credentials",
    "prompt_missing",
    "unsupported_number",
    "budget_exhausted",
)

# How many table rows the narrator is shown. A `count_by cwe` returns 25 and a
# `list_findings` up to 100; the prompt stays bounded, and the row cap is stated to the
# model so it does not describe the tail it cannot see.
MAX_ROWS_TO_MODEL = 25
# Free-text fields on a listing row are trimmed — the narrator needs the shape of the
# answer, not every explanation in full.
MAX_FIELD_CHARS = 400

_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.DOTALL)
_INT_RE = re.compile(r"\d+")

QUESTION_MAX_CHARS = 500

# Shown in the UI as starting points. Each one exercises a different `op`, so the buttons
# together demonstrate the whole closed query set.
SUGGESTED_QUESTIONS = (
    "Tổng quan báo cáo này có gì?",
    "Phân bố theo mức độ nghiêm trọng ra sao?",
    "Ma trận mức độ và độ tin cậy trông thế nào?",
    "Thống kê theo CWE, loại lỗi nào nhiều nhất?",
    "Tệp nào bị nhiều phát hiện nhất?",
    "Liệt kê các lỗi CWE-89",
    "Độ phủ kho tri thức thế nào?",
)


@dataclass
class ChatTurn:
    """One question and everything that produced its answer. Carries provenance rather
    than just text, because the page has to be able to say *how* it knows."""

    question: str
    spec: QuerySpec
    result: QueryResult
    answer: str
    route_source: RouteSource
    answer_source: AnswerSource
    route_failure: str | None = None
    answer_failure: str | None = None
    tokens: int = 0
    prompt_version: str | None = None
    prompt_sha256: str | None = None
    # Which query the model (or the router) actually asked for, as JSON — shown in the
    # "how this was answered" expander so a wrong answer is diagnosable.
    spec_json: str = ""
    notes: list[str] = field(default_factory=list)


# --- the spend guard ----------------------------------------------------------------
#
# The deployed instance is public and unauthenticated by decision (ADR 19). Until now that
# was safe because it held no key: the worst an anonymous visitor could do was read. Giving
# it a real key changes exactly one thing — the chat box becomes a way to spend somebody's
# money — so the key arrives together with a ceiling on what it can spend.
#
# This is a budget, not a security control. A determined abuser can open a new session, and
# nothing here authenticates anyone. What it guarantees is that the bill has a maximum: once
# the day's tokens are gone, `answer()` stops calling the model and falls back to the
# deterministic path, which is the same path the instance ran on before it had a key. The
# page keeps answering; it just answers plainly.
#
# The ledger is per-process and resets when the container restarts, so a redeploy grants a
# fresh day. That is a known looseness, written down rather than papered over: it bounds a
# runaway, it does not bill-meter to the cent.

DAILY_TOKEN_BUDGET_ENV = "CHAT_DAILY_TOKEN_BUDGET"
# Roughly 30–60 questions a day at this prompt size. Chosen to be useful for a demo and
# uninteresting to abuse, and overridable — set it to `0` to lift the ceiling entirely.
DEFAULT_DAILY_TOKEN_BUDGET = 150_000

# `0` and the empty string both mean "no ceiling"; anything unparseable falls back to the
# default rather than to unlimited, so a typo cannot silently uncap the spend.
UNLIMITED = 0


@dataclass
class _Ledger:
    """Tokens spent by the chat on one UTC day, in this process."""

    day: str = ""
    spent: int = 0


_ledger = _Ledger()


def _utc_day(today: str | None = None) -> str:
    return today or datetime.now(UTC).date().isoformat()


def daily_token_budget() -> int:
    """The day's ceiling in tokens, or `UNLIMITED`. A misspelled value resolves to the
    default, never to unlimited — the same fail-toward-safety rule `runtime_mode()` uses for
    `SCAN_UI_READONLY`, applied to money instead of to scanning."""
    raw = os.environ.get(DAILY_TOKEN_BUDGET_ENV, "").strip()
    if not raw:
        return DEFAULT_DAILY_TOKEN_BUDGET
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_DAILY_TOKEN_BUDGET
    return UNLIMITED if value <= 0 else value


def tokens_spent(today: str | None = None) -> int:
    """Tokens this process has spent today. A new UTC day zeroes the ledger on read, so no
    scheduler or background task is needed to roll it over."""
    day = _utc_day(today)
    if _ledger.day != day:
        return 0
    return _ledger.spent


def record_tokens(tokens: int, today: str | None = None) -> None:
    day = _utc_day(today)
    if _ledger.day != day:
        _ledger.day, _ledger.spent = day, 0
    _ledger.spent += max(0, int(tokens))


def budget_remaining(today: str | None = None) -> int | None:
    """Tokens left today, or `None` when there is no ceiling."""
    limit = daily_token_budget()
    if limit == UNLIMITED:
        return None
    return max(0, limit - tokens_spent(today))


def budget_exhausted(today: str | None = None) -> bool:
    remaining = budget_remaining(today)
    return remaining is not None and remaining <= 0


def reset_budget() -> None:
    """Test seam. Nothing in the app calls this — a restart is what clears the ledger in
    production, and that is deliberate."""
    _ledger.day, _ledger.spent = "", 0


def model_available() -> bool:
    """Whether a model call can even be attempted. Both values are required: a base URL
    with no key and a key with no base URL are each a guaranteed transport failure, and
    finding that out costs a round trip and a confusing error."""
    return bool(os.environ.get("OPENCODE_API_KEY", "").strip()) and bool(
        os.environ.get("OPENCODE_BASE_URL", "").strip()
    )


def default_model() -> str:
    return os.environ.get("CUSTOM_SCAN_MODEL", "").strip()


def load_chat_prompt(path: Path = CHAT_PROMPT_PATH) -> SystemPrompt:
    """Same loader, same hashing, same refusal-to-default as the analysis prompt — one
    file with two sections rather than two files, so a single `version:` and a single
    sha256 describe the whole conversational behaviour."""
    return load_system_prompt(path)


def _vocabulary(report) -> str:
    """The concrete values present in *this* report, handed to the router so it filters on
    something real. Without it the model routes to a plausible CWE that no finding has, and
    the page confidently answers zero."""
    lines = []
    for dimension in ("severity", "confidence", "cwe", "owasp", "tool", "analysis_source"):
        values = sorted({report_query._dimension_value(f, dimension) for f in report.findings})
        lines.append(f"- `{dimension}`: {', '.join(values)}")
    return "\n".join(lines)


def _router_turn(question: str, report) -> str:
    return "\n".join(
        [
            "## Câu hỏi của người dùng",
            "",
            question.strip()[:QUESTION_MAX_CHARS],
            "",
            "## Giá trị có thật trong báo cáo này",
            "",
            _vocabulary(report),
            "",
            f"Báo cáo có tổng cộng {len(report.findings)} phát hiện.",
            "",
            "Trả về đúng một đối tượng JSON theo lược đồ, không có gì khác.",
        ]
    )


def _trim_row(row: dict) -> dict:
    return {
        key: (value[:MAX_FIELD_CHARS] if isinstance(value, str) else value)
        for key, value in row.items()
    }


def _narrator_turn(question: str, result: QueryResult) -> str:
    shown = [_trim_row(row) for row in result.table[:MAX_ROWS_TO_MODEL]]
    lines = [
        "## Câu hỏi của người dùng",
        "",
        question.strip()[:QUESTION_MAX_CHARS],
        "",
        "## Truy vấn đã chạy",
        "",
        f"- Thao tác: `{result.op}`"
        + (f" theo chiều `{result.dimension}`" if result.dimension else ""),
        f"- Bộ lọc: {result.filters or 'không có'}",
        f"- Số phát hiện khớp bộ lọc: {result.total}",
        f"- Mô tả: {result.caption}",
    ]
    if result.note:
        lines.append(f"- Ghi chú: {result.note}")
    lines += [
        "",
        "## Bảng số liệu (sự thật — chỉ được dùng số ở đây)",
        "",
        "```json",
        json.dumps(shown, ensure_ascii=False, indent=2),
        "```",
    ]
    if len(result.table) > len(shown):
        lines.append(
            f"\nBảng còn {len(result.table) - len(shown)} dòng nữa không hiện ở đây — "
            "đừng mô tả phần bạn không nhìn thấy."
        )
    lines += ["", "Viết 2–4 câu tiếng Việt. Văn bản thuần, không JSON."]
    return "\n".join(lines)


def _allowed_numbers(result: QueryResult, question: str) -> set[int]:
    """Every integer a narration may legitimately contain: the counts and values in the
    table, the total, integers embedded in labels (CWE numbers, `A03`), the row count, and
    whatever the question itself already said."""
    allowed: set[int] = {result.total, len(result.table)}
    for row in result.table:
        for value in row.values():
            if isinstance(value, bool):
                continue
            if isinstance(value, int):
                allowed.add(value)
            elif isinstance(value, str):
                allowed.update(int(match) for match in _INT_RE.findall(value))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        allowed.update(int(m) for m in _INT_RE.findall(item))
    allowed.update(int(match) for match in _INT_RE.findall(question))
    # Percentages the prompt forbids but a model may still produce from two numbers it was
    # legitimately given. Allowing the arithmetically correct ones keeps the check aimed at
    # invention rather than at rounding.
    if result.total:
        for row in result.table:
            count = row.get("count")
            if isinstance(count, int):
                allowed.add(round(100.0 * count / result.total))
    # Small ordinals ("hai nhóm đầu", "top 3") are not claims about the data.
    allowed.update(range(11))
    return allowed


def _unsupported_numbers(text: str, result: QueryResult, question: str) -> list[int]:
    """Integers in the narration that the table cannot account for. This is the check that
    makes 'the model never counts' an enforced property rather than a prompt instruction —
    the same shape as the analysis agent throwing away a model-invented file path."""
    allowed = _allowed_numbers(result, question)
    return sorted({int(match) for match in _INT_RE.findall(text)} - allowed)


def _route_with_model(
    question: str, report, prompt: SystemPrompt, model: str
) -> tuple[QuerySpec | None, int, str | None, str]:
    """`(spec, tokens, failure_reason, detail)`. Never raises for a model problem — a bad
    route is a labelled fallback, not an error page."""
    system = _section(prompt.text, ROUTER_HEADING)
    if not system:
        return None, 0, "prompt_missing", f"thiếu section '## {ROUTER_HEADING}'"

    content, tokens, failure = _post_chat(
        [
            {"role": "system", "content": system},
            {"role": "user", "content": _router_turn(question, report)},
        ],
        model=model,
        timeout=CALL_TIMEOUT_SECONDS,
    )
    if failure or not content:
        return None, tokens, failure or "empty_response", ""

    text = content.strip()
    fence = _FENCE_RE.match(text)
    if fence:
        # The prompt forbids a fence; unwrapping one costs nothing and saves a fallback.
        text = fence.group(1)
    try:
        payload = json.loads(text)
    except ValueError:
        return None, tokens, "non_json", text[:200]

    try:
        return report_query.spec_from_dict(payload), tokens, None, ""
    except QuerySpecError as exc:
        return None, tokens, "spec_invalid", str(exc)


def _narrate_with_model(
    question: str, result: QueryResult, prompt: SystemPrompt, model: str
) -> tuple[str | None, int, str | None, str]:
    system = _section(prompt.text, NARRATOR_HEADING)
    if not system:
        return None, 0, "prompt_missing", f"thiếu section '## {NARRATOR_HEADING}'"

    content, tokens, failure = _post_chat(
        [
            {"role": "system", "content": system},
            {"role": "user", "content": _narrator_turn(question, result)},
        ],
        model=model,
        timeout=CALL_TIMEOUT_SECONDS,
    )
    if failure or not content:
        return None, tokens, failure or "empty_response", ""

    text = content.strip()
    invented = _unsupported_numbers(text, result, question)
    if invented:
        return (
            None,
            tokens,
            "unsupported_number",
            "con số không có trong bảng: " + ", ".join(str(n) for n in invented[:8]),
        )
    return text, tokens, None, ""


def answer(question: str, report, use_llm: bool = True, model: str | None = None) -> ChatTurn:
    """One question in, one fully-attributed `ChatTurn` out.

    Runs at most two model calls and always produces an answer. `use_llm=False` — or an
    environment with no credentials — takes the deterministic path end to end, which is
    reproducible and costs nothing."""
    question = (question or "").strip()
    notes: list[str] = []
    tokens = 0
    prompt: SystemPrompt | None = None

    model_id = (model or default_model()).strip()
    wants_llm = bool(use_llm) and model_available() and bool(model_id)

    route_failure: str | None = None
    answer_failure: str | None = None
    if use_llm and not wants_llm:
        route_failure = answer_failure = "no_credentials"

    # Checked before the prompt is even loaded: an exhausted budget is not an error, it is
    # the instance reverting to the deterministic path it shipped on. The turn is labelled
    # so the page can say so rather than passing a template answer off as a model one.
    if wants_llm and budget_exhausted():
        wants_llm = False
        route_failure = answer_failure = "budget_exhausted"
        notes.append(
            f"đã dùng hết hạn mức {daily_token_budget():,} token của hôm nay — "
            "câu hỏi này được trả lời bằng đường tất định"
        )

    if wants_llm:
        try:
            prompt = load_chat_prompt()
        except PromptMissingError as exc:
            prompt = None
            wants_llm = False
            route_failure = answer_failure = "prompt_missing"
            notes.append(str(exc))

    # --- step 1: route -----------------------------------------------------------
    spec: QuerySpec | None = None
    route_source: RouteSource = "keyword"
    if wants_llm and prompt is not None:
        spec, call_tokens, route_failure, detail = _route_with_model(
            question, report, prompt, model_id
        )
        tokens += call_tokens
        if spec is not None:
            route_source = "llm"
        elif detail:
            notes.append(f"định tuyến bằng mô hình thất bại ({route_failure}): {detail}")

    if spec is None:
        spec = report_query.route_keywords(question)
        route_source = "keyword"

    # --- step 2: run the query (always Python) -----------------------------------
    try:
        result = report_query.run_query(report, spec)
    except QuerySpecError as exc:
        # A validated spec should not fail here; if it somehow does, an overview is still a
        # true answer, and the note says what happened.
        notes.append(f"truy vấn không chạy được ({exc}) — đã lùi về tổng quan")
        spec = QuerySpec(op="overview")
        result = report_query.run_query(report, spec)

    # --- step 3: narrate ---------------------------------------------------------
    prose: str | None = None
    answer_source: AnswerSource = "template"
    if wants_llm and prompt is not None:
        prose, call_tokens, answer_failure, detail = _narrate_with_model(
            question, result, prompt, model_id
        )
        tokens += call_tokens
        if prose is not None:
            answer_source = "llm"
        elif detail:
            notes.append(f"diễn giải bằng mô hình bị loại ({answer_failure}): {detail}")

    if prose is None:
        prose = report_query.template_answer(result)
        answer_source = "template"

    # Charged after the fact, from what the provider actually reported — a call that failed
    # in transport reports zero and costs nothing, and a call that burned tokens before
    # being thrown out for inventing a number still counts against the ceiling. Billing
    # follows spend, not usefulness.
    record_tokens(tokens)

    return ChatTurn(
        question=question,
        spec=spec,
        result=result,
        answer=prose,
        route_source=route_source,
        answer_source=answer_source,
        route_failure=route_failure,
        answer_failure=answer_failure,
        tokens=tokens,
        prompt_version=prompt.version if prompt else None,
        prompt_sha256=prompt.sha256 if prompt else None,
        spec_json=json.dumps(
            {
                "op": spec.op,
                "dimension": spec.dimension,
                "filters": spec.filters,
                "limit": spec.limit,
            },
            ensure_ascii=False,
            sort_keys=True,
        ),
        notes=notes,
    )
