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

**A third path, added later: prebaked.** The suggested-question buttons are a fixed, short
list, and making a visitor wait ~20s for prose the same model already wrote yesterday buys
nothing. `scripts/bake_chat.py` runs each suggested question once against the real model and
records the prose it produced *together with the model id, the tokens it cost, and how long
it took*; `prebaked_answer()` serves that back instantly. Two rules keep this from becoming
a lie on the page:

* **Only the prose is cached.** The query still runs through `report_query` on every serve,
  so the table, the chart and the finding list are computed now, from the report on disk.
* **A stale cache is not served.** The bake records a fingerprint of the report it was baked
  against, and the recomputed numbers are re-checked against the cached prose by the same
  `_unsupported_numbers()` gate a live narration passes. Either check failing drops the turn
  back to the live path rather than showing prose that no longer matches its own table.
"""
from __future__ import annotations

import json
import os
import re
import time
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

CHAT_CACHE_PATH = ROOT / "data" / "analysis" / "chat_cache.json"

ROUTER_HEADING = "Định tuyến"
NARRATOR_HEADING = "Diễn giải"

RouteSource = Literal["llm", "keyword", "prebaked"]
AnswerSource = Literal["llm", "template", "prebaked"]

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
# A thousands separator inside a number, in either convention: `482,344` and `482.344` are
# one number, not two. See `_unsupported_numbers` for why this matters.
_GROUPED_DIGITS_RE = re.compile(r"(?<=\d)[.,](?=\d{3}(?!\d))")

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
    # Which model wrote the prose, or `None` when no model was involved (deterministic
    # path). Recorded rather than re-derived from the environment, because the environment
    # at render time is not necessarily the one that produced the answer — a prebaked turn
    # is served by an instance that may hold no key at all.
    model: str | None = None
    # Wall-clock to produce *this* turn, measured around the whole `answer()` call.
    elapsed_seconds: float = 0.0
    # Set only on the prebaked path: the model call happened at bake time, so its cost and
    # duration belong to that moment and must be labelled with it. A turn showing
    # `tokens=5077` that spent nothing just now would otherwise read as a fresh call.
    prebaked: bool = False
    baked_at: str | None = None
    baked_elapsed_seconds: float | None = None
    # What wrote the words at bake time. A bake where the model routed correctly but had its
    # narration rejected still cost tokens and still names a model — and the words in it were
    # written by `template_answer()`. Carrying this keeps the page from crediting the model
    # with prose it did not write, which the live path never does either.
    baked_answer_source: AnswerSource | None = None
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


def _ints_in(text: str) -> list[int]:
    """Every integer in `text`, with grouped digits joined first. Both sides of the gate read
    numbers the same way, so a figure written `482.344` in a table and `482,344` in a
    narration are the same number to both."""
    return [int(match) for match in _INT_RE.findall(_GROUPED_DIGITS_RE.sub("", text))]


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
                allowed.update(_ints_in(value))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        allowed.update(_ints_in(item))
    allowed.update(_ints_in(question))
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
    the same shape as the analysis agent throwing away a model-invented file path.

    Grouped digits are joined back up first. The table stores `482344` as an int and a model
    writing Vietnamese writes it `482.344`, which a bare `\\d+` scan reads as the two numbers
    482 and 344 — neither in the table, so a correctly-quoted figure was being thrown out as
    an invention. (Found by `scripts/bake_chat.py`: the overview answer, the first question
    anyone clicks, lost its model prose to exactly this.) Joining them is a *tightening*, not
    a loosening: an invented `4.823` now has to clear the gate as 4823 rather than slipping
    through as the harmless fragments 4 and 823."""
    allowed = _allowed_numbers(result, question)
    joined = _GROUPED_DIGITS_RE.sub("", text)
    return sorted({int(match) for match in _INT_RE.findall(joined)} - allowed)


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
    started = time.perf_counter()
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
        # The model is named only when it actually wrote something. A turn that fell back to
        # the template after a failed call spent tokens but produced no model prose, and
        # naming the model there would credit it with words it did not write.
        model=model_id if (route_source == "llm" or answer_source == "llm") else None,
        elapsed_seconds=time.perf_counter() - started,
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


# --- the prebaked path ----------------------------------------------------------------
#
# The suggested questions are a closed list of seven, and the report they ask about only
# changes when somebody reruns `scripts/analyze.py`. Paying the model twice per visitor to
# re-derive the same seven paragraphs is a cost with no reader-visible benefit — and the
# cost the reader *does* see is the ~20s wait.
#
# So the seven are baked once (`scripts/bake_chat.py`) and served from disk. What is baked
# is the prose and the route; what is not baked is a single number. The numbers are
# recomputed by `report_query` on every serve, which is what makes the check below possible
# and what keeps the chart, the table and the finding list honest even if the cache is old.

CACHE_VERSION = 1


def report_fingerprint(report) -> str:
    """Identifies the report a cache entry was baked against, cheaply.

    `generated_at` alone would do for the normal case (a rerun of the agent rewrites it),
    but a hand-edited or truncated `report.jsonl` keeps its sidecar timestamp — so the
    finding count rides along, and a report that lost findings stops matching."""
    meta = report.meta
    return f"{meta.generated_at}|{len(report.findings)}|{meta.prompt_sha256}"


def _cache_key(question: str) -> str:
    """Lookup key for a question. Case and surrounding space are not meaningful — the
    buttons send exact strings, but a visitor who retypes one by hand should still get the
    fast path."""
    return " ".join((question or "").split()).casefold()


def load_prebaked(path: Path = CHAT_CACHE_PATH) -> dict:
    """The bake file, or an empty cache. A missing file is the normal state of a fresh
    checkout and a corrupt one must not take the page down — either way the chat simply
    falls through to the live path it has always had."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(payload, dict) or payload.get("version") != CACHE_VERSION:
        return {}
    return payload


def prebaked_questions(path: Path = CHAT_CACHE_PATH) -> set[str]:
    """Which questions have a baked answer, as opaque lookup keys. Pair it with
    `is_prebaked()` — the UI uses this to say which buttons are instant rather than
    promising a speed it cannot deliver."""
    payload = load_prebaked(path)
    return {_cache_key(entry.get("question", "")) for entry in payload.get("entries", [])}


def is_prebaked(question: str, baked: set[str] | None = None, path: Path = CHAT_CACHE_PATH) -> bool:
    """Whether `question` has a baked answer. Pass `baked` to check a list of questions
    against one read of the file instead of one read each.

    This answers "is there an entry", not "will it be served" — `prebaked_answer()` can
    still reject a stale entry, and that is the check that decides."""
    return _cache_key(question) in (prebaked_questions(path) if baked is None else baked)


def prebaked_answer(question: str, report, path: Path = CHAT_CACHE_PATH) -> ChatTurn | None:
    """A baked answer for `question`, re-verified against the report on disk, or `None`.

    `None` is never an error — it means "answer this the ordinary way". Every rejection
    below is a case where serving the cache would put prose next to a table that no longer
    agrees with it, which is the one thing this path is not allowed to do."""
    started = time.perf_counter()
    payload = load_prebaked(path)
    if not payload:
        return None

    fingerprint = report_fingerprint(report)
    if payload.get("report_fingerprint") != fingerprint:
        return None

    key = _cache_key(question)
    entry = next(
        (item for item in payload.get("entries", []) if _cache_key(item.get("question", "")) == key),
        None,
    )
    if entry is None:
        return None

    prose = (entry.get("answer") or "").strip()
    if not prose:
        return None

    # The query is rerun, not restored. Everything numeric on the page therefore comes from
    # the same code path a live turn uses, and the cache contributes exactly one thing: words.
    try:
        spec = report_query.spec_from_dict(entry.get("spec") or {})
        result = report_query.run_query(report, spec)
    except QuerySpecError:
        return None

    # The same gate a live narration has to pass. If the report moved under the cache in a
    # way the fingerprint did not catch, the prose loses here instead of on screen.
    if _unsupported_numbers(prose, result, question):
        return None

    return ChatTurn(
        question=question.strip(),
        spec=spec,
        result=result,
        answer=prose,
        route_source="prebaked",
        answer_source="prebaked",
        tokens=int(entry.get("tokens") or 0),
        model=entry.get("model"),
        elapsed_seconds=time.perf_counter() - started,
        prebaked=True,
        baked_at=payload.get("baked_at"),
        baked_elapsed_seconds=entry.get("elapsed_seconds"),
        baked_answer_source=entry.get("answer_source"),
        prompt_version=entry.get("prompt_version"),
        prompt_sha256=entry.get("prompt_sha256"),
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
        notes=[
            (
                "câu trả lời dựng sẵn — lời văn lấy từ lần gọi mô hình lúc bake, "
                "còn mọi con số vẫn được tính lại từ báo cáo ngay lúc mở trang"
            )
        ],
    )


def bake_entry(turn: ChatTurn) -> dict:
    """One `ChatTurn` as a cache row. Defined here rather than in the baking script so the
    file's shape and its reader live in the same module."""
    return {
        "question": turn.question,
        "answer": turn.answer,
        "spec": {
            "op": turn.spec.op,
            "dimension": turn.spec.dimension,
            "filters": turn.spec.filters,
            "limit": turn.spec.limit,
        },
        "model": turn.model,
        "tokens": turn.tokens,
        "elapsed_seconds": round(turn.elapsed_seconds, 3),
        "route_source": turn.route_source,
        "answer_source": turn.answer_source,
        "prompt_version": turn.prompt_version,
        "prompt_sha256": turn.prompt_sha256,
    }


def bake_payload(
    report,
    turns: list[ChatTurn],
    baked_at: str | None = None,
    existing: dict | None = None,
) -> dict:
    """The cache file for `turns`, merged over `existing` when that describes the same report.

    Merging is what makes `--only` usable: re-baking one question after a prompt fix should
    cost one question, not seven. A cache baked against a *different* report is dropped
    rather than merged — half-old prose beside half-new numbers is the exact failure the
    fingerprint exists to prevent."""
    fingerprint = report_fingerprint(report)
    kept: list[dict] = []
    if existing and existing.get("report_fingerprint") == fingerprint:
        rebaked = {_cache_key(turn.question) for turn in turns}
        kept = [
            entry
            for entry in existing.get("entries", [])
            if _cache_key(entry.get("question", "")) not in rebaked
        ]
    return {
        "version": CACHE_VERSION,
        "report_fingerprint": fingerprint,
        "baked_at": baked_at or datetime.now(UTC).isoformat(timespec="seconds"),
        "entries": kept + [bake_entry(turn) for turn in turns],
    }
