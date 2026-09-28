FROM ghcr.io/astral-sh/uv:0.4.27-python3.12-bookworm-slim AS build

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev

FROM ghcr.io/astral-sh/uv:0.4.27-python3.12-bookworm-slim

WORKDIR /app
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1

COPY --from=build /app/.venv /app/.venv
COPY --from=build /app/src /app/src

RUN useradd --uid 10001 --create-home lcg
USER 10001

EXPOSE 8000
# Standard: HTTP-Service. Für das CI-Gate: `docker run ... lcg check ...`
CMD ["uvicorn", "lcg.api:app", "--host", "0.0.0.0", "--port", "8000"]
