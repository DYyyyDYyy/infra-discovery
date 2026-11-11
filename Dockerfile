FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.5.9 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src src
COPY rules rules
RUN uv sync --frozen --no-dev && useradd --create-home --uid 10001 discover && mkdir /data && chown discover /data
ENV PATH=/app/.venv/bin:$PATH USER=discover
USER discover
VOLUME /data
EXPOSE 8000
ENTRYPOINT ["discover", "--db", "/data/cmdb.sqlite"]
CMD ["serve", "--host", "0.0.0.0"]
