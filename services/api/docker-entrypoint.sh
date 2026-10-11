#!/bin/sh
set -eu

alembic upgrade head

if [ "${SLEEP_SEED_DEMO:-false}" = "true" ]; then
    python -m sleep_api.seed
fi

exec "$@"
