FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_COMPILE_BYTECODE=1
COPY --from=ghcr.io/astral-sh/uv:0.5 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev
ENV PATH="/app/.venv/bin:$PATH"
USER nobody
EXPOSE 8000
# One worker per container; scale with replicas so the HPA sees real CPU per pod.
CMD ["uvicorn", "ffpverify.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--loop", "uvloop", \
     "--http", "httptools", "--no-access-log", "--backlog", "4096"]
