"""LangSmith tracing for every LLM call in this project. Stdlib only.

Canonical copy: `scanner-agent/src/llm_trace.py`. Copied verbatim (byte for
byte, so a diff is meaningful) into:

  - `probe-gateway/src/safe_probe/llm_trace.py`
  - `juice-shop-scan/src/juiceshop_scan/llm/llm_trace.py`

Three copies rather than a shared package because each of those is a separate
git repository that has to run standalone, and two of the three are declared
**stdlib-only** in their own `AGENTS.md` -- which rules out the `langsmith`
SDK as much as it ruled out `requests` and `python-dotenv`. The module is
self-contained on purpose: nothing here imports from its own package, which is
what lets the three files stay identical.

Why it exists. Every LLM layer in this repo already appends its own audit line
(`data/llm/calls.jsonl`, `report.meta.json`, `run_ledger`), and those stay --
they are what makes a run re-derivable offline. What they cannot show is the
*shape* of a run: which prompt produced which retry, how a group's analysis
nests under a whole `analyze()`, where the tokens actually went. That is what
this sends to LangSmith.

Three rules, all load-bearing:

1. **Silent no-op without `LANGSMITH_API_KEY`.** The LLM layer is optional in
   every component here (`probe suite` works offline, `analyze --no-llm` works
   offline, tests never touch the network). Tracing is one layer further out
   than that, so it must never be the thing that breaks a run -- and must never
   make a test hit the network.
2. **Never raises.** Every public entry point swallows its own errors. A
   tracing bug that fails an LLM call would be worse than no tracing.
3. **Off the hot path.** Runs are queued and posted by one background thread;
   `finish()` does not wait for the network. Flushed at interpreter exit.

Env vars (real environment first, then the nearest `.env` files walking up from
this file -- the same precedence each component's own `load_env` uses):

  LANGSMITH_API_KEY    required; absent => tracing off
  LANGSMITH_PROJECT    default "ai-security-copilot"
  LANGSMITH_ENDPOINT   default "https://api.smith.langchain.com"
  LANGSMITH_TRACING    set to a falsey value to force tracing off with a key set

`LANGCHAIN_*` is accepted for each of those too, since that is what an already
exported shell environment is likely to be carrying.
"""

from __future__ import annotations

import atexit
import contextlib
import contextvars
import json
import os
import queue
import sys
import threading
import time
import types
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_ENDPOINT = "https://api.smith.langchain.com"
DEFAULT_PROJECT = "ai-security-copilot"

# Prompts here carry scanner output and target response bodies; a trace is a
# third-party service, so a long one is truncated rather than shipped whole.
MAX_FIELD_CHARS = 12_000

# Batching. Small on purpose: a scan is tens of calls, not thousands, and a
# short flush interval keeps the LangSmith view live while a run is going.
BATCH_MAX = 20
FLUSH_INTERVAL_S = 2.0
POST_TIMEOUT_S = 20
EXIT_FLUSH_TIMEOUT_S = 8.0

# Values that must never appear in a trace. Read by name from the environment
# at send time, so a key rotated mid-process is still caught.
_SECRET_ENV_VARS = (
    "OPENCODE_API_KEY",
    "PROBE_API_KEY",
    "LANGSMITH_API_KEY",
    "LANGCHAIN_API_KEY",
    "WEBUI_GITHUB_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
)

# The three copies of this file are three distinct modules to Python, so a
# module-level ContextVar would give each its own parent stack -- and a step
# opened by one copy would not adopt the LLM call made through another (webui
# imports both `safe_probe` and `security_agent`). One state object, parked in
# `sys.modules` under a name no real module can claim, is what makes the copies
# behave as one tracer. Spans are duck-typed across copies: `.run_id`,
# `.trace_id`, `.dotted_order` is the whole contract.
_STATE_KEY = "_llm_trace_shared_state_v1"


def _shared_state() -> Any:
    state = sys.modules.get(_STATE_KEY)
    if state is None:
        state = types.ModuleType(_STATE_KEY)
        state.current = contextvars.ContextVar("llm_trace_current", default=None)
        state.lock = threading.Lock()
        state.sender = None
        sys.modules[_STATE_KEY] = state
    return state


# -- configuration -----------------------------------------------------------


def _env_files() -> list[Path]:
    """`.env` files from here upward, nearest first.

    Each component reads its own `.env` (`probe-gateway/.env`,
    `juice-shop-scan/.env`, ...) while `LANGSMITH_API_KEY` lives in the
    repo-root one, two or three levels above. Walking up finds both, and the
    nearest still wins -- so a submodule checked out on its own, with no parent
    `.env`, simply traces nothing.
    """
    here = Path(__file__).resolve()
    return [parent / ".env" for parent in list(here.parents)[:6]]


def _env_value(names: tuple[str, ...]) -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    for path in _env_files():
        try:
            if not path.exists():
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                if key.strip() in names:
                    cleaned = value.strip().strip("'\"")
                    if cleaned:
                        return cleaned
        except OSError:
            continue
    return ""


def _truthy(value: str) -> bool:
    return value.strip().lower() not in ("", "0", "false", "no", "off")


class _Config:
    __slots__ = ("api_key", "enabled", "endpoint", "project")

    def __init__(self) -> None:
        self.api_key = _env_value(("LANGSMITH_API_KEY", "LANGCHAIN_API_KEY"))
        self.endpoint = (
            _env_value(("LANGSMITH_ENDPOINT", "LANGCHAIN_ENDPOINT")) or DEFAULT_ENDPOINT
        ).rstrip("/")
        self.project = _env_value(("LANGSMITH_PROJECT", "LANGCHAIN_PROJECT")) or DEFAULT_PROJECT
        # A placeholder key (`.env.example` ships `LANGSMITH_API_KEY=...`) is not
        # a key. Without this, a copied example file turns every run into 401s.
        placeholder = self.api_key in ("...", "changeme") or self.api_key.startswith("...")
        switch = _env_value(("LANGSMITH_TRACING", "LANGCHAIN_TRACING_V2", "LANGCHAIN_TRACING"))
        self.enabled = bool(self.api_key) and not placeholder and (not switch or _truthy(switch))

    def __repr__(self) -> str:
        return (
            f"_Config(endpoint={self.endpoint!r}, project={self.project!r}, "
            f"enabled={self.enabled}, api_key=***REDACTED***)"
        )


# -- the sender --------------------------------------------------------------


class _Sender:
    """One queue, one daemon thread, one POST per batch of finished runs.

    Runs are posted after they end (`/runs/batch` accepts a run with both
    `start_time` and `end_time`), so a live LangSmith view lags by up to
    `FLUSH_INTERVAL_S` plus the duration of the call itself. That is the price
    of not needing a second PATCH per run, and of never blocking the caller.
    """

    def __init__(self, config: _Config) -> None:
        self.config = config
        self.queue: queue.Queue = queue.Queue(maxsize=2048)
        self.sent = 0
        self.dropped = 0
        self.failures = 0
        self.last_error: str | None = None
        self._thread = threading.Thread(target=self._loop, name="llm-trace", daemon=True)
        self._thread.start()
        atexit.register(self.flush)

    def submit(self, run: dict[str, Any]) -> None:
        try:
            self.queue.put_nowait(run)
        except queue.Full:
            # Dropping a trace is the correct failure: it is telemetry, and the
            # audit log that the report actually depends on is written elsewhere.
            self.dropped += 1

    def _loop(self) -> None:
        while True:
            batch = self._drain()
            if batch:
                self._post(batch)

    def _drain(self) -> list[dict[str, Any]]:
        batch: list[dict[str, Any]] = []
        try:
            batch.append(self.queue.get(timeout=FLUSH_INTERVAL_S))
        except queue.Empty:
            return batch
        while len(batch) < BATCH_MAX:
            try:
                batch.append(self.queue.get_nowait())
            except queue.Empty:
                break
        return batch

    def _post(self, batch: list[dict[str, Any]]) -> None:
        body = json.dumps({"post": batch}, ensure_ascii=False, default=str)
        request = urllib.request.Request(
            f"{self.config.endpoint}/runs/batch",
            data=_redact(body).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.config.api_key,
                # LangSmith is fronted by a CDN that answers the default
                # `Python-urllib/*` with a 403 in some regions -- the same thing
                # the model gateway does (see each `llm.py`'s USER_AGENT note).
                "User-Agent": "ai-security-copilot-llm-trace/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=POST_TIMEOUT_S) as response:
                response.read()
            self.sent += len(batch)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:200]
            self.failures += len(batch)
            self.last_error = f"HTTP {exc.code}: {detail}"
        except Exception as exc:  # noqa: BLE001 -- telemetry must never escape
            self.failures += len(batch)
            self.last_error = f"{type(exc).__name__}: {exc}"

    def flush(self, timeout: float = EXIT_FLUSH_TIMEOUT_S) -> None:
        """Drain what is queued, synchronously. Registered with `atexit` so a
        CLI that finishes its scan and exits still ships its last batch."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            batch = []
            while len(batch) < BATCH_MAX:
                try:
                    batch.append(self.queue.get_nowait())
                except queue.Empty:
                    break
            if not batch:
                return
            self._post(batch)


def _sender() -> _Sender | None:
    """The one sender shared by every copy of this module, or None if off."""
    state = _shared_state()
    with state.lock:
        if state.sender is None:
            config = _Config()
            if not config.enabled:
                return None
            state.sender = _Sender(config)
        return state.sender


def enabled() -> bool:
    """True when a real key is configured. Cheap enough to call per request."""
    try:
        return _sender() is not None
    except Exception:  # noqa: BLE001
        return False


def status() -> dict[str, Any]:
    """What a health check or a debug page can show without leaking the key."""
    try:
        sender = _sender()
    except Exception as exc:  # noqa: BLE001
        return {"enabled": False, "error": f"{type(exc).__name__}: {exc}"}
    if sender is None:
        return {"enabled": False, "reason": "LANGSMITH_API_KEY chưa được đặt"}
    return {
        "enabled": True,
        "project": sender.config.project,
        "endpoint": sender.config.endpoint,
        "sent": sender.sent,
        "failures": sender.failures,
        "dropped": sender.dropped,
        "queued": sender.queue.qsize(),
        "last_error": sender.last_error,
    }


def flush(timeout: float = EXIT_FLUSH_TIMEOUT_S) -> None:
    """Ship everything queued. Called at exit; exposed for tests and for a
    long-lived server that wants a trace visible before it answers."""
    with contextlib.suppress(Exception):
        sender = _sender()
        if sender is not None:
            sender.flush(timeout)


# -- payload hygiene ---------------------------------------------------------


def _redact(text: str) -> str:
    for name in _SECRET_ENV_VARS:
        secret = os.environ.get(name, "").strip()
        # Short values are not credentials; substituting them would corrupt
        # ordinary prose (`GITHUB_TOKEN=` empty, a model name, a `0`).
        if len(secret) >= 12 and secret in text:
            text = text.replace(secret, "***REDACTED***")
    return text


def _clip(value: Any) -> Any:
    if isinstance(value, str):
        if len(value) <= MAX_FIELD_CHARS:
            return value
        return value[:MAX_FIELD_CHARS] + f"... [{len(value) - MAX_FIELD_CHARS} ký tự bị cắt]"
    if isinstance(value, dict):
        return {k: _clip(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clip(v) for v in value]
    return value


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(moment: datetime) -> str:
    return moment.isoformat()


def _segment(moment: datetime, run_id: str) -> str:
    """One `dotted_order` component: LangSmith orders siblings by this string,
    so it has to be the start time at microsecond resolution plus the id."""
    return moment.strftime("%Y%m%dT%H%M%S%f") + "Z" + run_id


# -- spans -------------------------------------------------------------------


class Span:
    """One LangSmith run, in flight. Created by `trace_step` / `trace_llm`.

    A no-op span (`live=False`) is handed out when tracing is off, so call
    sites can treat the context manager as unconditional.
    """

    __slots__ = (
        "_ended",
        "dotted_order",
        "error",
        "inputs",
        "live",
        "metadata",
        "name",
        "outputs",
        "parent_run_id",
        "run_id",
        "run_type",
        "start",
        "trace_id",
    )

    def __init__(
        self,
        *,
        live: bool,
        name: str = "",
        run_type: str = "chain",
        inputs: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        parent: Any | None = None,
    ) -> None:
        self.live = live
        self.name = name
        self.run_type = run_type
        self.inputs = inputs or {}
        self.outputs: dict[str, Any] = {}
        self.metadata = dict(metadata or {})
        self.error: str | None = None
        self._ended = False
        self.start = _now()
        self.run_id = str(uuid.uuid4())
        if parent is not None:
            self.parent_run_id = parent.run_id
            self.trace_id = parent.trace_id
            self.dotted_order = parent.dotted_order + "." + _segment(self.start, self.run_id)
        else:
            self.parent_run_id = None
            self.trace_id = self.run_id
            self.dotted_order = _segment(self.start, self.run_id)

    # The setters are the whole call-site API, so each one is a no-op when the
    # span is dead rather than something a caller has to guard.

    def set_outputs(self, **outputs: Any) -> None:
        if self.live:
            self.outputs.update(outputs)

    def set_metadata(self, **metadata: Any) -> None:
        if self.live:
            self.metadata.update(metadata)

    def set_error(self, error: str) -> None:
        if self.live:
            self.error = error[:2000]

    def record_llm_response(
        self,
        *,
        content: str | None = None,
        tool_calls: list[dict[str, Any]] | None = None,
        usage: dict[str, Any] | None = None,
        finish_reason: str | None = None,
    ) -> None:
        """Record a chat completion in the shape LangSmith renders as a message.

        `usage` goes to `usage_metadata` under the names LangSmith costs and
        totals on -- an OpenAI-shaped `usage` block maps straight across, and a
        gateway that reports nothing simply gets no token counts.
        """
        if not self.live:
            return
        message: dict[str, Any] = {"role": "assistant", "content": content or ""}
        if tool_calls:
            message["tool_calls"] = tool_calls
        choice: dict[str, Any] = {"message": message}
        if finish_reason:
            choice["finish_reason"] = finish_reason
        self.outputs["choices"] = [choice]
        if usage:
            self.outputs["usage"] = usage
            prompt_tokens = usage.get("prompt_tokens")
            completion_tokens = usage.get("completion_tokens")
            total = usage.get("total_tokens")
            if prompt_tokens is None and completion_tokens is None and total is None:
                return
            self.metadata.setdefault("usage_metadata_source", "gateway")
            self.outputs["usage_metadata"] = {
                "input_tokens": int(prompt_tokens or 0),
                "output_tokens": int(completion_tokens or 0),
                "total_tokens": int(total or (prompt_tokens or 0) + (completion_tokens or 0)),
            }

    def payload(self) -> dict[str, Any]:
        sender = _sender()
        project = sender.config.project if sender else DEFAULT_PROJECT
        end = _now()
        run: dict[str, Any] = {
            "id": self.run_id,
            "trace_id": self.trace_id,
            "dotted_order": self.dotted_order,
            "name": self.name,
            "run_type": self.run_type,
            "start_time": _iso(self.start),
            "end_time": _iso(end),
            "inputs": _clip(self.inputs),
            "outputs": _clip(self.outputs),
            "extra": {"metadata": _clip(self.metadata)},
            "session_name": project,
        }
        if self.parent_run_id:
            run["parent_run_id"] = self.parent_run_id
        if self.error:
            run["error"] = self.error
        return run

    def finish(self) -> None:
        if not self.live or self._ended:
            return
        self._ended = True
        with contextlib.suppress(Exception):
            sender = _sender()
            if sender is not None:
                sender.submit(self.payload())


_DEAD = None


def _dead_span() -> Span:
    """One shared no-op span. Safe to share: nothing mutates a dead span."""
    global _DEAD
    if _DEAD is None:
        _DEAD = Span(live=False)
    return _DEAD


def current_span() -> Any | None:
    """The innermost open span, whichever copy of this module opened it."""
    try:
        return _shared_state().current.get()
    except Exception:  # noqa: BLE001
        return None


@contextlib.contextmanager
def trace(
    name: str,
    *,
    run_type: str = "chain",
    inputs: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> Iterator[Span]:
    """Open one run, nested under whatever run is already open.

    Exceptions are recorded on the span and re-raised -- the caller's error
    handling is unchanged by being traced.
    """
    try:
        live = enabled()
    except Exception:  # noqa: BLE001
        live = False
    if not live:
        yield _dead_span()
        return

    state = _shared_state()
    try:
        span = Span(
            live=True,
            name=name,
            run_type=run_type,
            inputs=inputs or {},
            metadata=metadata,
            parent=state.current.get(),
        )
        token = state.current.set(span)
    except Exception:  # noqa: BLE001
        yield _dead_span()
        return

    try:
        yield span
    except BaseException as exc:
        with contextlib.suppress(Exception):
            span.set_error(f"{type(exc).__name__}: {exc}")
        raise
    finally:
        with contextlib.suppress(Exception):
            state.current.reset(token)
        span.finish()


def trace_step(
    name: str,
    *,
    inputs: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    run_type: str = "chain",
) -> Any:
    """A step that is not itself an LLM call: an agent loop, a retry wrapper, a
    whole `analyze()`. Groups the calls made inside it into one trace."""
    return trace(name, run_type=run_type, inputs=inputs, metadata=metadata)


def trace_llm(
    name: str,
    *,
    model: str,
    messages: list[dict[str, Any]] | None = None,
    inputs: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    run_type: str = "llm",
) -> Any:
    """One request to a model. `messages` is stored in the chat shape LangSmith
    renders as a conversation; `inputs` is for the non-chat cases (embeddings)."""
    payload = dict(inputs or {})
    if messages is not None:
        payload["messages"] = messages
    meta = {"ls_model_name": model, "ls_provider": "opencode-zen", **(metadata or {})}
    return trace(name, run_type=run_type, inputs=payload, metadata=meta)
