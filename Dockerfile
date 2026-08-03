FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

ENV PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Dependencies resolve in their own layer, ahead of the source COPY below: a source
# edit then always rebuilds the final layer instead of being served from a cached one.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

COPY . .

# Deployed instances are read-only by default; a host that wants the full panel has to
# say so explicitly rather than inherit scanning by omission.
ENV SCAN_UI_READONLY=1 \
    PORT=8501

EXPOSE 8501

CMD ["sh", "-c", "streamlit run src/app.py --server.address 0.0.0.0 --server.port ${PORT} --server.headless true"]
