FROM python:3.14-slim-bookworm AS scanner-assets

ARG TARGETARCH
COPY deploy/fetch_scanners.py /tmp/fetch_scanners.py
RUN python /tmp/fetch_scanners.py "${TARGETARCH}" /scanner-bin

FROM python:3.14-slim-bookworm AS application

ARG NMAP_DEBIAN_VERSION=7.93+dfsg1-1
RUN apt-get update \
    && apt-get install -y --no-install-recommends "nmap=${NMAP_DEBIAN_VERSION}" ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.12.7 /uv /usr/local/bin/uv
COPY --from=scanner-assets /scanner-bin/httpx /usr/local/bin/httpx
COPY --from=scanner-assets /scanner-bin/nuclei /usr/local/bin/nuclei

WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src/ src/
RUN uv sync --locked --no-dev --no-cache \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin scopelens \
    && mkdir -p /var/lib/scopelens \
    && chown 10001:10001 /var/lib/scopelens \
    && chmod 0700 /var/lib/scopelens

COPY deploy/api-entrypoint.sh /usr/local/bin/scopelens-api-entrypoint
RUN chmod 0755 /usr/local/bin/scopelens-api-entrypoint

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SCOPELENS_CONFIG=/etc/scopelens/scope.toml \
    SCOPELENS_ARTIFACTS=/var/lib/scopelens

USER 10001:10001
ENTRYPOINT ["scopelens-api-entrypoint"]
