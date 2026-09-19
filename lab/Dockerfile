FROM python:3.14-slim-bookworm AS target-base
WORKDIR /srv
USER 10001:10001
CMD ["python", "-m", "http.server", "8000", "--bind", "0.0.0.0", "--directory", "/srv"]

FROM target-base AS target
COPY --chown=10001:10001 lab/www/ /srv/

FROM target-base AS fixed-target
COPY --chown=10001:10001 lab/fixed/ /srv/

FROM python:3.14-slim-bookworm AS scanner
RUN apt-get update && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src/ src/
COPY --from=ghcr.io/astral-sh/uv:0.12.7 /uv /usr/local/bin/uv
RUN uv sync --locked --no-dev --no-cache \
    && mkdir /artifacts && chown 10001:10001 /artifacts && chmod 700 /artifacts
COPY lab/scope.toml lab/scope.toml
ENV PATH="/app/.venv/bin:$PATH"
USER 10001:10001
ENTRYPOINT ["scopelens"]
CMD ["scan-nmap", "/app/lab/scope.toml", "--profile", "lab", "--artifacts", "/artifacts"]
