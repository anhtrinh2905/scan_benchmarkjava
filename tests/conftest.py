"""Suite-wide guard: no test may ship a LangSmith trace.

`llm_trace` reads `LANGSMITH_API_KEY` from the real environment *and* from the
`.env` files above it, so on a developer machine with a key configured the
tracing layer would be live inside the test suite -- posting runs from tests to
a real project, in a background thread, past the `_offline` fixture that only
stubs `requests.post`.

Set at import time rather than in a fixture: `llm_trace` builds its sender once,
lazily, and the first test to touch an LLM path would otherwise have built a
real one before any fixture ran.
"""
import os

os.environ["LANGSMITH_TRACING"] = "0"
