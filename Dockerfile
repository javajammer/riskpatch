FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app
RUN useradd --create-home --uid 1000 app
COPY pyproject.toml uv.lock ./
COPY src ./src
COPY deploy/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh && uv sync --frozen --no-dev
ENV PATH="/app/.venv/bin:$PATH"
ENTRYPOINT ["/entrypoint.sh"]
USER app
CMD ["riskpatch", "service"]
