#!/bin/sh
set -eu

: "${SCOPELENS_DATABASE_URL:?set SCOPELENS_DATABASE_URL}"
: "${SCOPELENS_API_TOKEN:?set SCOPELENS_API_TOKEN}"
: "${SCOPELENS_CORS_ORIGIN:?set SCOPELENS_CORS_ORIGIN}"

umask 077
scopelens validate-config "${SCOPELENS_CONFIG}"
scopelens history-init
exec scopelens api-serve \
    "${SCOPELENS_CONFIG}" \
    --artifacts "${SCOPELENS_ARTIFACTS}" \
    --cors-origin "${SCOPELENS_CORS_ORIGIN}" \
    --container-bind
